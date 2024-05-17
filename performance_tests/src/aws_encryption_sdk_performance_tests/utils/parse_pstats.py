import pstats
import sys

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 parse_pstats.py <pstats_filename>")
        sys.exit(1)

    pstats_filename = sys.argv[1]

    # Load the .pstats file
    stats = pstats.Stats(pstats_filename)

    # Get the total runtime
    total_runtime = stats.total_tt

    # stats.sort_stats('cumtime').print_stats()
    # print(stats.get_stats_profile())
    print('total_runtime', total_runtime)
