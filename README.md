# AWS Health → Slack Notifier

A Python script that monitors AWS Health events and sends notifications to Slack.

## Features

- **Multiple Modes:**
  - `once`: One-time scan for new scheduled-change events.
  - `daemon`: Continuous polling for new events.
  - `listen`: Slack Socket-Mode bot for interactive queries.
  - `diag`: Diagnostic mode to verify connections.
  - `test`: Self-tests for persistence and path resolution.
  - `health`: Health check to monitor script status.

- **AWS Health Integration:**
  - Fetches upcoming scheduled-change events from AWS Health.
  - Requires AWS Business or Enterprise Support plan.

- **Slack Integration:**
  - Posts notifications to a specified Slack channel.
  - Supports interactive queries via Slack Socket-Mode.

- **Robust Error Handling:**
  - Graceful handling of AWS and Slack API errors.
  - Comprehensive logging.

- **Rate Limiting:**
  - Prevents API throttling for AWS Health and Slack.

- **Signal Handling:**
  - Graceful shutdown on SIGTERM/SIGINT.

## Prerequisites

- **Python 3.8 – 3.12**
- **AWS Business or Enterprise Support plan**
- **IAM Permissions:**
  - `sts:GetCallerIdentity`
  - `health:DescribeEvents`
  - `health:DescribeEventDetails`
- **Slack Bot:**
  - Bot User OAuth Token (`xoxb-...`)
  - App-Level Token (`xapp-...`) for Socket-Mode

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Configure `config.ini`:**
   ```ini
   [SLACK]
   BOT_TOKEN = xoxb-your-token-here
   APP_TOKEN = xapp-your-token-here
   CHANNEL = #ops-alerts
   POLL_SECONDS = 900

   [AWS]
   REGION = us-east-1
   PROFILE = default

   [LOGGING]
   LEVEL = INFO
   FILE = aws-notifier.log
   MAX_SIZE = 10485760
   BACKUP_COUNT = 5
   ```

## Usage

### **One-Time Scan:**
```bash
python3 awsNotifier.py once
```

### **Daemon Mode (Continuous Polling):**
```bash
python3 awsNotifier.py daemon
```

### **Slack Socket-Mode (Interactive):**
```bash
python3 awsNotifier.py listen
```

### **Diagnostic Mode:**
```bash
python3 awsNotifier.py diag
```

### **Self-Test:**
```bash
python3 awsNotifier.py test
```

### **Health Check:**
```bash
python3 awsNotifier.py health
```

## Troubleshooting

### **Common Issues:**

1. **"No module named 'boto3'":**
   - Ensure `boto3` is installed for the correct Python version:
     ```bash
     python3 -m pip install boto3
     ```

2. **"SubscriptionRequiredException":**
   - AWS Health API requires a Business or Enterprise Support plan.
   - If you only have a Developer plan, consider using the AWS Personal Health Dashboard RSS feed or CloudWatch Events.

3. **Slack API Errors:**
   - Verify your Slack tokens and channel name in `config.ini`.
   - Ensure your Slack bot has the required permissions (`chat:write`, `app_mentions:read`).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
