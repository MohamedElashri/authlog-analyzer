# AuthLog Analyzer

## Overview
AuthLog Analyzer is a Python script designed to parse and analyze authentication logs, typically found in `/var/log/auth.log` on Unix systems. It provides a detailed breakdown of both successful and failed login attempts, organizing this data into various categories for easier analysis and monitoring.

## Features
- **Extraction of Login Details:** Parses each line in the authentication log to extract key details such as time, username, IP address, and port.
- **Identification of Success and Failure Attempts:** Distinguishes between successful and failed login attempts.
- **Failed Attempts Analysis:**
  - Identifies failed login attempts, including those targeted at the root user.
  - Extracts and displays the username and IP address associated with each failed attempt.
- **IP Address Analysis:**
  - Counts the number of attempts made from each IP address.
  - Utilizes a free IP geolocation API to identify the country of origin for each IP address.
  - Presents a summary of attempt counts per country, reducing API calls by caching country data.
- **Username Attempt Counts:** Tracks and displays the number of attempts made using each username.
- **Presentation in Tabular Format:** Uses the `prettytable` library to neatly display the analyzed data in table format for easy reading.

## Installation
1. **Clone the Repository:**

```bash
git clone https://github.com/your-username/authlog-analyzer.git
```

2. **Install Dependencies:**
- Ensure Python is installed on your system.
- Install required Python packages:
  ```
  pip install prettytable requests
  ```

## Usage
- Place the script in a directory with read access to `/var/log/auth.log`.
- Run the script using Python:
  
```bash
python authlog_analyzer.py
```
- View the output tables with detailed login attempt information.

## Output Tables
1. **Failed Login Attempts:** Lists all failed login attempts with timestamps, usernames, IP addresses, and ports.
2. **Failed Login Attempts for Root:** Specifically lists failed attempts to access the root user.
3. **Successful Login Attempts:** Details successful logins, including the session type.
4. **IP Address Attempt Counts:** Shows the number of attempts from each IP address.
5. **Username Attempt Counts:** Displays the number of attempts associated with each username.
6. **Country Attempt Counts:** Presents the number of attempts from each country, based on IP geolocation.

## Limitations and Notes
- The script is dependent on the format of `/var/log/auth.log`. Variations in log format may require adjustments to the parsing logic.
- IP geolocation is performed using a free service (`ip-api.com`). Be mindful of rate limits and potential inaccuracies in geolocation data.
- Ensure compliance with privacy laws and ethical considerations when using external APIs for data processing.

## Contributing
Contributions to the AuthLog Analyzer are welcome! Feel free to fork the repository, make changes, and submit pull requests. For major changes or new features, please open an issue first to discuss what you would like to change.

## License
Distributed under the GPL3 License. See `LICENSE` for more information.


