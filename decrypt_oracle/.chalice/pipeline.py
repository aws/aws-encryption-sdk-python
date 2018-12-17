"""
Generate the CloudFormation template for the deployment pipeline.
"""
import argparse
import getpass
import logging
from typing import Iterable

import boto3
import troposphere
from awacs import (
    aws as AWS,
    awslambda as LAMBDA,
    cloudformation as CLOUDFORMATION,
    cloudwatch as CLOUDWATCH,
    codebuild as CODEBUILD,
    codepipeline as CODEPIPELINE,
    iam as IAM,
    logs as LOGS,
    s3 as S3,
    sts as STS,
)
from botocore.exceptions import ClientError
from troposphere import GetAtt, Ref, Sub, Template, codebuild, codepipeline, iam, s3

APPLICATION_NAME = "AwsEncryptionSdkDecryptOraclePython"
PIPELINE_STACK_NAME = "{}DeployPipeline".format(APPLICATION_NAME)
CODEBUILD_IMAGE = "aws/codebuild/python:3.6.5"
BUILDSPEC = "decrypt_oracle/.chalice/buildspec.yaml"
GITHUB_REPO = "aws-encryption-sdk-python"
WAITER_CONFIG = dict(Delay=10)
_LOGGER = logging.getLogger("Decrypt Oracle Build Pipeline Deployer")


class AllowEverywhere(AWS.Statement):
    """Shortcut for creating IAM Statements that Allow to Resource "*"."""

    def __init__(self, *args, **kwargs):
        my_kwargs = dict(Effect=AWS.Allow, Resource=["*"])
        my_kwargs.update(kwargs)
        super(AllowEverywhere, self).__init__(*args, **my_kwargs)


def _service_assume_role(service: str) -> AWS.Policy:
    """Build and return the IAM AssumeRolePolicy for use in service roles."""
    return AWS.Policy(
        Statement=[
            AWS.Statement(
                Effect=AWS.Allow,
                Action=[STS.AssumeRole],
                Principal=AWS.Principal("Service", ["{}.amazonaws.com".format(service)]),
            )
        ]
    )


def _codebuild_role() -> iam.Role:
    """Build and return the IAM Role resource to be used by CodeBuild to run the build project."""
    policy = iam.Policy(
        "CodeBuildPolicy",
        PolicyName="CodeBuildPolicy",
        PolicyDocument=AWS.PolicyDocument(
            Statement=[
                AllowEverywhere(Action=[LOGS.CreateLogGroup, LOGS.CreateLogStream, LOGS.PutLogEvents]),
                AllowEverywhere(Action=[S3.GetObject, S3.GetObjectVersion, S3.PutObject]),
            ]
        ),
    )
    return iam.Role("CodeBuildRole", AssumeRolePolicyDocument=_service_assume_role(CODEBUILD.prefix), Policies=[policy])


def _codebuild_builder(role: iam.Role, application_bucket: s3.Bucket) -> codebuild.Project:
    """Build and return the CodeBuild Project resource to be used to build the decrypt oracle."""
    artifacts = codebuild.Artifacts(Type="CODEPIPELINE")
    environment = codebuild.Environment(
        ComputeType="BUILD_GENERAL1_SMALL",
        Image=CODEBUILD_IMAGE,
        Type="LINUX_CONTAINER",
        EnvironmentVariables=[codebuild.EnvironmentVariable(Name="APP_S3_BUCKET", Value=Ref(application_bucket))],
    )
    source = codebuild.Source(Type="CODEPIPELINE", BuildSpec=BUILDSPEC)
    return codebuild.Project(
        "{}Build".format(APPLICATION_NAME),
        Artifacts=artifacts,
        Environment=environment,
        Name=APPLICATION_NAME,
        ServiceRole=Ref(role),
        Source=source,
    )


def _pipeline_role(buckets: Iterable[s3.Bucket]) -> iam.Role:
    """Build and return the IAM Role resource to be used by CodePipeline to run the pipeline."""
    bucket_statements = [
        AWS.Statement(
            Effect=AWS.Allow,
            Action=[S3.GetBucketVersioning, S3.PutBucketVersioning],
            Resource=[GetAtt(bucket, "Arn") for bucket in buckets],
        ),
        AWS.Statement(
            Effect=AWS.Allow,
            Action=[S3.GetObject, S3.PutObject],
            Resource=[Sub("${{{bucket}.Arn}}/*".format(bucket=bucket.title)) for bucket in buckets],
        ),
    ]
    policy = iam.Policy(
        "PipelinePolicy",
        PolicyName="PipelinePolicy",
        PolicyDocument=AWS.PolicyDocument(
            Statement=bucket_statements
            + [
                AllowEverywhere(Action=[CLOUDWATCH.Action("*"), IAM.PassRole]),
                AllowEverywhere(Action=[LAMBDA.InvokeFunction, LAMBDA.ListFunctions]),
                AllowEverywhere(
                    Action=[
                        CLOUDFORMATION.CreateStack,
                        CLOUDFORMATION.DeleteStack,
                        CLOUDFORMATION.DescribeStacks,
                        CLOUDFORMATION.UpdateStack,
                        CLOUDFORMATION.CreateChangeSet,
                        CLOUDFORMATION.DeleteChangeSet,
                        CLOUDFORMATION.DescribeChangeSet,
                        CLOUDFORMATION.ExecuteChangeSet,
                        CLOUDFORMATION.SetStackPolicy,
                        CLOUDFORMATION.ValidateTemplate,
                    ]
                ),
                AllowEverywhere(Action=[CODEBUILD.BatchGetBuilds, CODEBUILD.StartBuild]),
            ]
        ),
    )
    return iam.Role(
        "CodePipelinesRole", AssumeRolePolicyDocument=_service_assume_role(CODEPIPELINE.prefix), Policies=[policy]
    )


def _cloudformation_role() -> iam.Role:
    """Build and return the IAM Role resource to be used by the pipeline to interact with CloudFormation."""
    policy = iam.Policy(
        "CloudFormationPolicy",
        PolicyName="CloudFormationPolicy",
        PolicyDocument=AWS.PolicyDocument(Statement=[AllowEverywhere(Action=[AWS.Action("*")])]),
    )
    return iam.Role(
        "CloudFormationRole", AssumeRolePolicyDocument=_service_assume_role(CLOUDFORMATION.prefix), Policies=[policy]
    )


def _pipeline(
    pipeline_role: iam.Role,
    cfn_role: iam.Role,
    codebuild_builder: codebuild.Project,
    artifact_bucket: s3.Bucket,
    github_owner: str,
    github_branch: str,
    github_access_token: troposphere.AWSProperty,
) -> codepipeline.Pipeline:
    """Build and return the CodePipeline pipeline resource."""
    _source_output = "SourceOutput"
    get_source = codepipeline.Stages(
        Name="Source",
        Actions=[
            codepipeline.Actions(
                Name="PullSource",
                RunOrder="1",
                OutputArtifacts=[codepipeline.OutputArtifacts(Name=_source_output)],
                ActionTypeId=codepipeline.ActionTypeId(
                    Category="Source", Owner="ThirdParty", Version="1", Provider="GitHub"
                ),
                Configuration=dict(
                    Owner=github_owner,
                    Repo=GITHUB_REPO,
                    OAuthToken=Ref(github_access_token),
                    Branch=github_branch,
                    PollForSourceChanges=True,
                ),
            )
        ],
    )
    _compiled_cfn_template = "CompiledCfnTemplate"
    _changeset_name = "{}ChangeSet".format(APPLICATION_NAME)
    _stack_name = "{}Stack".format(APPLICATION_NAME)
    do_build = codepipeline.Stages(
        Name="Build",
        Actions=[
            codepipeline.Actions(
                Name="BuildChanges",
                RunOrder="1",
                InputArtifacts=[codepipeline.InputArtifacts(Name=_source_output)],
                OutputArtifacts=[codepipeline.OutputArtifacts(Name=_compiled_cfn_template)],
                ActionTypeId=codepipeline.ActionTypeId(
                    Category="Build", Owner="AWS", Version="1", Provider="CodeBuild"
                ),
                Configuration=dict(ProjectName=Ref(codebuild_builder)),
            )
        ],
    )
    stage_changeset = codepipeline.Actions(
        Name="StageChanges",
        RunOrder="1",
        ActionTypeId=codepipeline.ActionTypeId(Category="Deploy", Owner="AWS", Version="1", Provider="CloudFormation"),
        InputArtifacts=[codepipeline.InputArtifacts(Name=_compiled_cfn_template)],
        Configuration=dict(
            ActionMode="CHANGE_SET_REPLACE",
            ChangeSetName=_changeset_name,
            RoleArn=GetAtt(cfn_role, "Arn"),
            Capabilities="CAPABILITY_IAM",
            StackName=_stack_name,
            TemplatePath="{}::decrypt_oracle/transformed.yaml".format(_compiled_cfn_template),
        ),
    )
    deploy_changeset = codepipeline.Actions(
        Name="Deploy",
        RunOrder="2",
        ActionTypeId=codepipeline.ActionTypeId(Category="Deploy", Owner="AWS", Version="1", Provider="CloudFormation"),
        Configuration=dict(
            ActionMode="CHANGE_SET_EXECUTE",
            ChangeSetName=_changeset_name,
            StackName=_stack_name,
            OutputFileName="StackOutputs.json",
        ),
        OutputArtifacts=[codepipeline.OutputArtifacts(Name="AppDeploymentValues")],
    )
    deploy = codepipeline.Stages(Name="Deploy", Actions=[stage_changeset, deploy_changeset])
    artifact_store = codepipeline.ArtifactStore(Type="S3", Location=Ref(artifact_bucket))
    return codepipeline.Pipeline(
        "{}Pipeline".format(APPLICATION_NAME),
        RoleArn=GetAtt(pipeline_role, "Arn"),
        ArtifactStore=artifact_store,
        Stages=[get_source, do_build, deploy],
    )


def _build_template(github_owner: str, github_branch: str) -> Template:
    """Build and return the pipeline template."""
    template = Template(Description="CI/CD pipeline for Decrypt Oracle powered by the AWS Encryption SDK for Python")
    github_access_token = template.add_parameter(
        troposphere.Parameter(
            "GithubPersonalToken", Type="String", Description="Personal access token for the github repo.", NoEcho=True
        )
    )
    application_bucket = template.add_resource(s3.Bucket("ApplicationBucket"))
    artifact_bucket = template.add_resource(s3.Bucket("ArtifactBucketStore"))
    builder_role = template.add_resource(_codebuild_role())
    builder = template.add_resource(_codebuild_builder(builder_role, application_bucket))
    # add codepipeline role
    pipeline_role = template.add_resource(_pipeline_role(buckets=[application_bucket, artifact_bucket]))
    # add cloudformation deploy role
    cfn_role = template.add_resource(_cloudformation_role())
    # add codepipeline
    template.add_resource(
        _pipeline(
            pipeline_role=pipeline_role,
            cfn_role=cfn_role,
            codebuild_builder=builder,
            artifact_bucket=artifact_bucket,
            github_owner=github_owner,
            github_branch=github_branch,
            github_access_token=github_access_token,
        )
    )
    return template


def _stack_exists(cloudformation) -> bool:
    """Determine if the stack has already been deployed."""
    try:
        cloudformation.describe_stacks(StackName=PIPELINE_STACK_NAME)

    except ClientError as error:
        if error.response["Error"]["Message"] == "Stack with id {name} does not exist".format(name=PIPELINE_STACK_NAME):
            return False
        raise

    else:
        return True


def _update_existing_stack(cloudformation, template: Template, github_token: str) -> None:
    """Update a stack."""
    _LOGGER.info("Updating existing stack")

    # 3. update stack
    cloudformation.update_stack(
        StackName=PIPELINE_STACK_NAME,
        TemplateBody=template.to_json(),
        Parameters=[dict(ParameterKey="GithubPersonalToken", ParameterValue=github_token)],
        Capabilities=["CAPABILITY_IAM"],
    )
    _LOGGER.info("Waiting for stack update to complete...")
    waiter = cloudformation.get_waiter("stack_update_complete")
    waiter.wait(StackName=PIPELINE_STACK_NAME, WaiterConfig=WAITER_CONFIG)
    _LOGGER.info("Stack update complete!")


def _deploy_new_stack(cloudformation, template: Template, github_token: str) -> None:
    """Deploy a new stack."""
    _LOGGER.info("Bootstrapping new stack")

    # 2. deploy template
    cloudformation.create_stack(
        StackName=PIPELINE_STACK_NAME,
        TemplateBody=template.to_json(),
        Parameters=[dict(ParameterKey="GithubPersonalToken", ParameterValue=github_token)],
        Capabilities=["CAPABILITY_IAM"],
    )
    _LOGGER.info("Waiting for stack to deploy...")
    waiter = cloudformation.get_waiter("stack_create_complete")
    waiter.wait(StackName=PIPELINE_STACK_NAME, WaiterConfig=WAITER_CONFIG)
    _LOGGER.info("Stack deployment complete!")


def _deploy_or_update_template(template: Template, github_token: str) -> None:
    """Update a stack, deploying a new stack if nothing exists yet."""
    cloudformation = boto3.client("cloudformation")

    if _stack_exists(cloudformation):
        return _update_existing_stack(cloudformation=cloudformation, template=template, github_token=github_token)

    return _deploy_new_stack(cloudformation=cloudformation, template=template, github_token=github_token)


def _setup_logging() -> None:
    """Set up logging."""
    logging.basicConfig(level=logging.INFO)


def main(args=None):
    """Entry point for CLI."""
    _setup_logging()

    parser = argparse.ArgumentParser(description="Pipeline deployer")
    parser.add_argument("--github-user", required=True, help="What Github user should be used?")
    parser.add_argument("--github-branch", required=False, default="master", help="What Github branch should be used?")

    parsed = parser.parse_args(args)

    access_token = getpass.getpass("Github personal token:")

    template = _build_template(github_owner=parsed.github_user, github_branch=parsed.github_branch)
    _deploy_or_update_template(template=template, github_token=access_token)


if __name__ == "__main__":
    main()
