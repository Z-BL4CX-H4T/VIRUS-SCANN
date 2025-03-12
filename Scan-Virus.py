import requests
import hashlib
import os
import json
import platform
import time
import random
from rich.console import Console
from rich.table import Table
from rich import print
from time import sleep

API_KEY = ""

console = Console()

def display_ascii():
    ascii_art = """
[bold green]
██╗   ██╗██╗██████╗ ██╗   ██╗███████╗      ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗
██║   ██║██║██╔══██╗██║   ██║██╔════╝      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║
██║   ██║██║██████╔╝██║   ██║███████╗█████╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║╚════╝╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║      ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝
           [red]BY MR P3T0K[/red]
[/bold green]
"""
    console.print(ascii_art)

def loading_animation(text):
    console.print(f"[bold cyan]{text}[/bold cyan]")
    animation = "█" * 40
    for i in range(0, 41):
        console.print(f"[bold green]{animation[:i]}{'▒' * (40 - i)} {int((i/40)*100)}%[/bold green]", end="\r")
        sleep(0.1)
    print("\n[bold green]✓ Scan complete, displaying results...[/bold green]")

def get_valid_path(path):
    system = platform.system()
    if system == "Windows":
        return path.replace("/", "\\")
    return path

def scan_files(file_paths):
    for file_path in file_paths:
        file_path = get_valid_path(file_path)
        if not os.path.isfile(file_path):
            console.print(f"[ERROR] File '{file_path}' not found.", style="bold red")
            continue

        loading_animation(f"Scanning File: {file_path}...")

        if os.path.getsize(file_path) > 32 * 1024 * 1024:
            console.print(f"[ERROR] File '{file_path}' exceeds 32 MB limit.", style="bold red")
            continue

        with open(file_path, 'rb') as file:
            file_hash = hashlib.md5(file.read()).hexdigest()

        params = {'apikey': API_KEY, 'resource': file_hash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

        try:
            result = response.json()
        except requests.exceptions.JSONDecodeError:
            console.print(f"[ERROR] Invalid response from VirusTotal.", style="bold red")
            continue

        if 'response_code' not in result or result['response_code'] != 1:
            console.print(f"[INFO] File {os.path.basename(file_path)} not found in VirusTotal database.", style="yellow")
            continue

        display_detailed_results("File Scan Result", os.path.basename(file_path), result)

def scan_url(urls):
    for url in urls:
        loading_animation(f"Scanning URL: {url}...")
        params = {'apikey': API_KEY, 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)

        try:
            result = response.json()
        except requests.exceptions.JSONDecodeError:
            console.print(f"[ERROR] Invalid response from VirusTotal.", style="bold red")
            continue

        if 'response_code' not in result or result['response_code'] != 1:
            console.print(f"[INFO] URL '{url}' not found in VirusTotal database.", style="yellow")
            continue

        display_detailed_results("URL Scan Result", url, result)

def display_detailed_results(title, item, data):
    table = Table(title=f"{title}: {item}")
    table.add_column("Positive Detections", style="red")
    table.add_column("Total Scans", style="green")
    table.add_column("Detecting Vendors", style="yellow")
    table.add_column("Threat Category", style="cyan")
    table.add_column("Scan Date", style="magenta")

    positives = data['positives']
    total = data['total']

    detecting_vendors = []
    threat_categories = []

    for vendor, detail in data['scans'].items():
        if detail['detected']:
            detecting_vendors.append(vendor)
            threat_categories.append(detail['result'])

    table.add_row(
        str(positives),
        str(total),
        ", ".join(detecting_vendors) if detecting_vendors else "None",
        ", ".join(threat_categories) if threat_categories else "None",
        data.get('scan_date', 'Not available')
    )

    console.print(table)

def menu():
    display_ascii()
    while True:
        console.print("""
[bold cyan]=== Malware Scanner ===[/bold cyan]
1. Scan 1 URL
2. Scan Multiple URLs
3. Scan 1 File
4. Scan Multiple Files
5. Scan 1 Folder
6. Scan Multiple Folders
7. Exit
""", style="green")

        choice = input("Select an option: ")

        if choice == "1":
            url = input("Enter URL: ")
            scan_url([url])
        elif choice == "2":
            urls = input("Enter URLs (separate with commas): ").split(",")
            scan_url([url.strip() for url in urls])
        elif choice == "3":
            file_path = input("Enter file path: ")
            scan_files([file_path])
        elif choice == "4":
            file_paths = input("Enter file paths (separate with commas): ").split(",")
            scan_files([path.strip() for path in file_paths])
        elif choice == "5":
            folder_path = input("Enter folder path: ")
            scan_files([os.path.join(folder_path, file) for file in os.listdir(folder_path)])
        elif choice == "6":
            folder_paths = input("Enter folder paths (separate with commas): ").split(",")
            for folder in folder_paths:
                scan_files([os.path.join(folder.strip(), file) for file in os.listdir(folder.strip())])
        elif choice == "7":
            console.print("[INFO] Exiting the program. Goodbye!", style="bold green")
            break
        else:
            console.print("[ERROR] Invalid choice! Please try again.", style="bold red")

if __name__ == "__main__":
    menu()
