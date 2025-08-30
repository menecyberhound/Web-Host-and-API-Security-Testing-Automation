# Web Security Scanner 🛡️

Hey there! This is a super cool security scanning tool that helps find potential problems in websites. Think of it like a security guard that checks every door and window of a house to make sure it's safe! 

## What Does It Do? 🤔

1. **Website Scanning**: It can check any website for security problems
2. **Scheduled Scans**: You can set it up to check websites automatically (like having a security guard do rounds every hour!)
3. **Nice Dashboard**: Shows all the problems it finds in pretty charts and tables
4. **Risk Levels**: Shows how serious each problem is (like a traffic light system - red for dangerous, yellow for medium, green for minor issues)

## How It's Built 🏗️

The application is built using these main parts:

- **Flask** (Python web framework) - Think of it as the brain of our security guard
- **ZAP** (Security Scanner) - This is like the security guard's tools (flashlight, keys, etc.)
- **SQLite** - This is like the security guard's notebook where they write down everything they find
- **Docker** - Think of this as the security guard's uniform - it makes sure everything works the same way everywhere

## How to Set It Up 🚀

### Local Setup (On Your Computer)

1. First, make sure you have these installed:
   - Docker (like a special box that keeps all our tools organized)
   - Python (the language our security guard speaks)

2. Clone this project:
   ```bash
   git clone [your-repository-url]
   cd security-scanner
   ```

3. Start the application:
   ```bash
   docker-compose up -d
   ```

That's it! Visit `http://localhost:8080` in your web browser to see the dashboard.

### AWS EC2 Deployment 🌐

Let's deploy this to the internet! Here's how:

1. **Create an EC2 Instance**:
   - Go to AWS Console
   - Click "Launch Instance"
   - Choose "Ubuntu Server 20.04 LTS"
   - Pick "t2.medium" (we need some muscle for scanning!)
   - Create a new key pair and download it
   - Launch the instance!

2. **Connect to Your Instance**:
   ```bash
   chmod 400 your-key.pem
   ssh -i your-key.pem ubuntu@your-ec2-public-ip
   ```

3. **Install Required Software**:
   ```bash
   # Update the system
   sudo apt-get update
   sudo apt-get upgrade -y

   # Install Docker
   sudo apt-get install docker.io -y
   sudo systemctl start docker
   sudo systemctl enable docker
   sudo usermod -aG docker ubuntu

   # Install Docker Compose
   sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

4. **Copy Your Files**:
   ```bash
   # From your local machine
   scp -i your-key.pem -r ./security-scanner ubuntu@your-ec2-public-ip:~/
   ```

5. **Start the Application**:
   ```bash
   cd security-scanner
   docker-compose up -d
   ```

## How Everything Works 🔍

### The Main Parts

1. **app.py** - The Main Brain 🧠
   - Controls everything that happens
   - Handles web pages and button clicks
   - Manages the security scans
   - Stores results in the database

2. **zap_scanner.py** - The Security Guard 👮
   - Does the actual security checking
   - Looks for problems in websites
   - Reports back what it finds

3. **risk_engine.py** - The Risk Analyzer 📊
   - Decides how serious each problem is
   - Organizes problems by importance
   - Helps prioritize what needs fixing

4. **templates/** - The Pretty Part 🎨
   - Contains all the web pages
   - Shows charts and tables
   - Makes everything look nice

### Database Structure 📁

We use SQLite with three main tables:

1. **scans**
   - Stores information about each scan
   - When it happened
   - What website was scanned
   - How many problems were found

2. **alerts**
   - Stores each problem found
   - How serious it is
   - Where exactly it was found
   - What kind of problem it is

3. **scheduled_scans**
   - Keeps track of automatic scans
   - When they should run
   - Which websites to check
   - How often to check them

## Features in Detail 🌟

### 1. Running a Scan
- Type in a website address
- Click "Start Scan"
- Watch the progress bar
- See results when it's done!

### 2. Scheduling Scans
- Choose when to scan (daily, weekly, monthly)
- Pick what time
- The system remembers and does it automatically

### 3. Viewing Results
- Nice charts show overall security status
- Tables list all problems found
- Can sort and filter results
- Export results to CSV files

### 4. Risk Levels
- **High** (Red) 🔴 - Needs fixing right away!
- **Medium** (Yellow) 🟡 - Should fix soon
- **Low** (Blue) 🔵 - Fix when you can
- **Info** (Gray) ⚪ - Just good to know

## Safety Tips ⚠️

1. Always get permission before scanning websites
2. Don't scan websites you don't own
3. Be careful with sensitive data
4. Keep your API keys secret

## Need Help? 🆘

If something goes wrong:
1. Check the logs in `security_scanner.log`
2. Make sure Docker is running
3. Check your internet connection
4. Make sure the website you're scanning is up

## Fun Facts! 🎈

- The scanner can find over 100 different types of security problems
- It's like having a security team working 24/7
- It can help make the internet safer!

## Contributing 🤝

Want to help make this better? You can:
1. Report bugs you find
2. Suggest new features
3. Help improve the code
4. Write better documentation

## License 📜

This project is open source! That means anyone can use it and help make it better!

---

Made with ❤️ by your security team

Remember: Use your powers for good! Always get permission before scanning websites!
