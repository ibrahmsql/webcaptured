class Colors:
    Reset = "\033[0m"
    BrightGreen = "\033[1;92m"
    BrightBlue = "\033[1;94m"
    BrightYellow = "\033[1;93m"
    BrightMagenta = "\033[1;95m"
    BrightCyan = "\033[1;96m"
    BrightRed = "\033[1;91m"
    BrightWhite = "\033[1;97m"

def display_banner():
    """Display colored banner with satellite ASCII art"""
    banner = r"""
       .-""""""-.
      /          \
     |   .-""""-.  |
     |  /        \ |
     | |   .--.   ||
     | |  /    \  ||
     | |  \    /  ||
     | |   '--'   ||
     |  \        / |
     |   '-____-'  |
      \    ____   /
       |  [____] |
       |    ||   |
       |    ||   |
       |    ||   |
       |   *||*  |
       |  |    | |
       |  |____| |
       |         |
       '---------'
    """
    
    # Split the banner into lines for coloring
    lines = banner.strip().split('\n')
    
    # Color each line differently
    colored_lines = []
    colors = [
        Colors.BrightGreen,
        Colors.BrightBlue,
        Colors.BrightYellow,
        Colors.BrightMagenta,
        Colors.BrightCyan,
        Colors.BrightRed
    ]
    
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        colored_lines.append(f"{color}{line}{Colors.Reset}")
    
    # Print the colored banner
    print("\n" + "\n".join(colored_lines))
    
    # Print the info under the satellite
    print(f"\n{Colors.BrightYellow}        WEBCAPTURE {Colors.Reset}")
    print(f"{Colors.BrightCyan}     Developer: ibrahimsql {Colors.Reset}")
    print(f"{Colors.BrightMagenta}    *Charming OSINT Tool {Colors.Reset}")
    print(f"{Colors.BrightGreen}─" * 40 + Colors.Reset)

if __name__ == "__main__":
    # Test the banner
    display_banner()