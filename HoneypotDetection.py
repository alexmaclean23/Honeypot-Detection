import os
import datetime

# Input banner
def input_banner():
    print()
    print("#############################################################")
    print("#              Honeypot Detection with Python               #")
    print("#                      by Alex Maclean                      #")
    print("#############################################################")
    print()
    input("         Press enter to initiate honeypot detection. ")
    print()
    print()

# Obtain username of primary user
def get_username():
    global username
    username = input("What is the username of the primary user of this system? ")
    print("Working...")
    print()

# Create directories to scan
def generate_directories():
    global windowsFiles
    global windowsConfigurations
    desktopWindows = "C:/Users/" + username + "/Desktop/"
    documentsWindows = "C:/Users/" + username + "/Documents/"
    downloadsWindows = "C:/Users/" + username + "/Downloads/"
    picturesWindows = "C:/Users/" + username + "/Pictures/"
    videosWindows = "C:/Users/" + username + "/Videos/"
    musicWindows = "C:/Users/" + username + "/Music/"
    mediaPlayer = "C:/Program Files/Windows Media Player/en-US/"
    photoViewer = "C:/Program Files/Windows Media Player/en-US/"
    multimediaPlatform = "C:/Program Files/Windows Multimedia Platform/"
    portableDevices = "C:/Program Files/Windows Multimedia Platform/"
    windowsFiles = [desktopWindows, documentsWindows, downloadsWindows, picturesWindows, videosWindows, musicWindows]
    windowsConfigurations = [mediaPlayer, photoViewer, multimediaPlatform, portableDevices]

# Scan file histories in selected directories
def scan_files():
    global oldestFileAge
    global youngestFileAge
    modificationTimes = []
    for directory in windowsFiles:
        for file in os.listdir(directory):
            if ("." in file):
                modificationTime = str(os.path.getmtime(directory + file)).split(".")[0]
                modificationTimes.append(modificationTime)
    youngestFileAge = max(modificationTimes)
    oldestFileAge = min(modificationTimes)

# Scan configuration dates in selected directories
def scan_configurations():
    global oldestConfigurationAge
    global youngestConfigurationAge
    modificationTimes = []
    for directory in windowsConfigurations:
        for file in os.listdir(directory):
            if ("." in file):
                modificationTime = str(os.path.getmtime(directory + file)).split(".")[0]
                modificationTimes.append(modificationTime)
    youngestConfigurationAge = max(modificationTimes)
    oldestConfigurationAge = min(modificationTimes)

# Convert the modification info from epoch to datetime
def convert_dates():
    global dates
    youngestFile = datetime.datetime.fromtimestamp(int(youngestFileAge)).strftime('%c')
    oldestFile = datetime.datetime.fromtimestamp(int(oldestFileAge)).strftime('%c')
    youngestConfiguration = datetime.datetime.fromtimestamp(int(youngestConfigurationAge)).strftime('%c')
    oldestConfiguration = datetime.datetime.fromtimestamp(int(oldestConfigurationAge)).strftime('%c')
    dates = "The most recent file modification occured on {}, while the least recent file modification occured on {}.\nThe most recent configuration change occured on {}, while the least recent configuration change occured on {}.".format(youngestFile, oldestFile, youngestConfiguration, oldestConfiguration)

# Compare the times between modifications and changes
def compare_values():
    global ranges
    fileRange = int(youngestFileAge) - int(oldestFileAge)
    configurationRange = int(youngestConfigurationAge) - int(oldestConfigurationAge)
    mixedRange = int(youngestFileAge) - int(oldestConfigurationAge)
    ranges = [fileRange, configurationRange, mixedRange]

# Calculate the likelihood that the system is a honeypot
def calculate_likelihood():
    global honeypotLikelihood
    fileEstimation = ranges[0] * 0.01
    if (fileEstimation > 100):
        fileEstimation = 100
    configurationEstimation = ranges[1] * 0.01
    if (configurationEstimation > 100):
        configurationEstimation = 100
    mixedEstimation = ranges[2] * 0.01
    if (mixedEstimation > 100):
        mixedEstimation = 100
    totalEstimation = str(100 - ((fileEstimation * 0.25) + (configurationEstimation * 0.15) + (mixedEstimation * 0.60))) + "%"
    honeypotLikelihood = "Based on these results, there is a {} chance that this system is a honeypot.".format(totalEstimation)

# Output banner
def output_banner():
    print()
    print("                     ###################")
    print("                     #     Results     #")
    print("                     ###################")
    print()
    print(dates)
    print()
    print(honeypotLikelihood)
    print()

# Main function that drives the rest of the script
def main():
    input_banner()
    get_username()
    generate_directories()
    scan_files()
    scan_configurations()
    convert_dates()
    compare_values()
    calculate_likelihood()
    output_banner()

# Call to main function
if __name__ == "__main__":
    main()