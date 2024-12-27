import subprocess
from mistralai import Mistral
import os
import json
from colorama import Fore, Style, init
from tqdm import tqdm
import time
import threading
import paramiko

# Initialize colorama
init(autoreset=True)
INFORMATION = []
SCRIPTS = []
api_key = os.getenv("MISTRAL_API_KEY")
client = Mistral(api_key=api_key)
model = "mistral-small-latest"

def execute_command(command, new_terminal=False):
    """
    Execute a terminal command, display the output in a terminal-like view,
    and return the terminal log as a string.
    """
    print(Fore.CYAN + "Terminal Command Executor")
    print(Fore.YELLOW + command)
    SCRIPTS.append(command)
    print(SCRIPTS)
    if command.lower() == "exit":
        print(Fore.YELLOW + "Exiting the program.")
        return "Exiting the program."

    try:
        if new_terminal:
            # Open a new terminal window
            subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', command])
            return "Command executed in a new terminal window."
        else:
            # Run the command locally
            result = subprocess.run(command, shell=True, text=True, capture_output=True)
            output = result.stdout.strip()
            error = result.stderr.strip()

        # Combine output and error for the terminal log
        terminal_log = f"Output:\n{output}\n\n" if output else ""
        terminal_log += f"Error:\n{error}" if error else ""

        # Print the terminal log
        if terminal_log:
            print(Fore.GREEN + terminal_log)
        else:
            print(Fore.GREEN + "Command executed successfully with no output.")

        return terminal_log if terminal_log else "Command executed successfully with no output."

    except Exception as e:
        error_message = f"An error occurred: {e}"
        print(Fore.RED + error_message)
        return error_message

def ask_ai(message):
    prompt = get_summary_of_execution(message)
    messages = [{"role": "user", "content": prompt}]

    # Start the progress bar in a separate thread
    progress_bar = tqdm(total=100, desc=Fore.MAGENTA + "Waiting for AI response", ncols=70)

    def update_progress():
        while progress_bar.n < progress_bar.total:
            progress_bar.update(1)
            time.sleep(0.1)

    thread = threading.Thread(target=update_progress)
    thread.start()

    # Make the API call
    try:
        response = client.chat.complete(model=model, messages=messages)
    except Exception as e:
        print(Fore.RED + f"Error making API call: {e}")
        return []

    # Stop the progress bar
    progress_bar.n = progress_bar.total
    progress_bar.close()
    thread.join()
    json_content = response.choices[0].message.content.strip()

    # Remove the ```json markers
    if json_content.startswith('```json') and json_content.endswith('```'):
        json_content = json_content[len('```json'):-len('```')].strip()

    # Log the raw JSON content for debugging
    print(Fore.YELLOW + "Raw JSON content from AI response:")
    # Ensure the JSON content is properly formatted
    try:
        json_data = json.loads(json_content)
    except json.JSONDecodeError as e:
        print(Fore.RED + f"Error parsing JSON: {e}")
        return []

    # Print the steps section
    steps = json_data.get("steps", [])
    print(Fore.BLUE + json.dumps(steps, indent=2))

    return steps

def get_summary_of_execution(content):
    return f"""
    I am a cybersecurity student tasked with exploiting a machine located in my virtual lab. My goal is to gain remote code execution (RCE) on the target machine.
    Analyze the provided content: {content}, and identify the next possible step to exploit vulnerabilities or gather more information. Your response should include detailed, specific steps that help me move towards achieving RCE.

    Key points to consider:
    - Focus on identifying vulnerable services or open ports on the machine.
    - Recommend tools for scanning and exploiting these vulnerabilities (e.g., Nmap, Nikto, Metasploit, Hydra, John the Ripper, etc.).
    - Suggest specific commands, scripts, or techniques for further exploitation.
    - If applicable, provide code snippets or shell scripts that can aid in the exploitation process.
    - Ensure no repetitive scripts and avoid providing irrelevant tools.

    Your response should be in valid JSON format with the following structure:

    {{
      "steps": [
        {{
          "step": 1,
          "details": "summary of the step (e.g., 'Scan for open ports and services')",
          "requirements": "dependencies or prerequisites for the step (e.g., 'Nmap 7.80')",
          "pre_install_scripts": "installation scripts or commands (e.g., 'sudo apt install nmap')",
          "script": ["nmap -sV 192.383.33.46"],
          "code": "any additional code needed for the task (e.g., Python script, Metasploit command)",
          "extension": "file extension if code exists (e.g., .py, .sh)",
          "usefulInformation": ["useful information extracted from the previous analysis (e.g., 'port 22 is open and running OpenSSH 7.9')"]
        }}
      ],
      "message": "A detailed description of the attack vector, including any caveats or additional notes."
    }}

    If no useful information is identified, make `usefulInformation: []` and skip providing a script. Additionally, ensure that the scripts are not duplicated and are directly relevant to achieving the goal of remote code execution.
    """

def command_loop(results, depth=0):
    if depth > 5:  # Limit the recursion depth to avoid infinite loops
        print(Fore.RED + "Maximum recursion depth reached. Exiting command loop.")
        return

    response = ask_ai(results)  # Fetch AI response
    for item in response:
        print(Fore.GREEN + f'Starting step {item["step"]}')
        print(Fore.WHITE + item['details'])
        if item.get('script'):
            for inform in item['usefulInformation']:
                INFORMATION.append(inform)  # Add information to the list
            for script in item['script']:
                new_terminal = any(tool in script for tool in ["nc", "msfconsole"])
                if script not in SCRIPTS:
                    result = execute_command(script, new_terminal)
                    command_loop(result, depth + 1)

def main():
    ip = input('Enter IP address: ')
    command = 'sudo nmap -sV ' + ip
    result = execute_command(command)
    print(Fore.MAGENTA + '*******************************************')
    command_loop(result)

if __name__ == "__main__":
    main()
