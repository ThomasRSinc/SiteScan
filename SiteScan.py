#################################################################
# Thomas Sinclair						#   TESTED WITH:        #
# 2001836@uad.ac.uk						# Kali Linux 2022.3		#
# 23-May-2023							# cURL 7.84, dirb 2.22	#
# 										# Nikto 2.1.6, Python-	#
# SiteScan - A web-app basic security   # -3.10, SSLScan 2.0.15,#
# scanner, for Linux. Best run on       # whatweb 0.5.5,		#
# Kali Linux due to requirements.       # wget 1.21.3, 			#
#################################################################

# Imports (+ their use in the code + install if non-standard)
import argparse			# Argument parsing
import datetime			# Date and time functionality
import magic			# File-type identification ~ pip install python-magic
import os				# Directory and filesystem-related operations
import pyinputplus		# Input validiation ~ pip install pyinputplus
import requests			# HTTP-related operations ~ pip install requests
import shutil			# Check path of executable
import socket			# Check whether a port is open
import subprocess		# Create new process for executing certain commands
import sys				# System-specific parameters and functions, such as exit()
import time				# Time-related operations, such as sleep()
import validators		# Data validation (email, IP etc.) ~ pip install validators



# ~~~ PROCEDURAL (ORDERED) ~~~

# Parse core arguments (used for startup initalisation)
def getArgs():
	# Create the parser
	parser = argparse.ArgumentParser("", formatter_class=argparse.RawTextHelpFormatter)
	
	# Add argument groups
	reqArgs = parser.add_argument_group("required arguments")
	optArgs = parser.add_argument_group("optional arguments")
	
	# Add required arguments
	reqArgs.add_argument("target", help="The target IPv4 address, HTTP(S) URL, or Domain")			# These "positionals" don't require -switch, but are still required somewhere
	
	# Add optional arguments (store as 'False' value by default)
	# (store_true automatically creates a default value of 'False' for reasons)
	optArgs.add_argument("-p", "--port", required=False, action="store", type=int, choices=[80,443], help="Specific application port/protocol to target (takes precedence!)")
	optArgs.add_argument("-login", "--loginpath", required=False, action="store", help="Relative path to login page (e.g. '/login/')")
	optArgs.add_argument("-user", "--username", required=False, action="store", help="Username to use for login")
	optArgs.add_argument("-pass", "--password", required=False, action="store", help="Password to use for login")
	optArgs.add_argument("-M", "--modify", required=False, action="store_true", help="Modify/Edit normal script behaviour \n...")	#Capital is deliberate to "separate" it from regular args
	optArgs.add_argument("-all", "--runall", required=False, action="store_true", help="Run ALL tests (takes precedence!)")		# Treats all test args as if they were set using args individually
	optArgs.add_argument("-ck", "--cookies", required=False, action="store_true", help="Run Cookie usage test")
	optArgs.add_argument("-cmt", "--comments", required=False, action="store_true", help="Run Code Comments search")
	optArgs.add_argument("-df", "--defaults", required=False, action="store_true", help="Run Default Files search")
	optArgs.add_argument("-dir", "--dirb", required=False, action="store_true", help="Run Dirb scan")
	optArgs.add_argument("-enc", "--encryption", required=False, action="store_true", help="Run Encryption analysis")
	optArgs.add_argument("-ent", "--entry", required=False, action="store_true", help="Run Entry Point search")
	optArgs.add_argument("-hd", "--header", required=False, action="store_true", help="Run HTTP Header analysis")
	optArgs.add_argument("-nk", "--nikto", required=False, action="store_true", help="Run Nikto scan")
	optArgs.add_argument("-ww", "--whatweb", required=False, action="store_true", help="Run WhatWeb scan")
	optArgs.add_argument("-wg", "--wget", required=False, action="store_true", help="Run Wget spider scan and file download (all)")
	
	# Parse the arguments
	args = parser.parse_args()

	# Declare [global] variables, initialise if necessary
	global target, port, login, modifyBehaviour, runTest	# all [optional] args default to 'None' if not present, unless default value is specified otherwise (see below)
	login = {}
	runTest = {												# args set to 'False' by default and will update these keys accordingly when setting (below) if required
		"cookies": True,
		"comments": True,
		"defaults": True,
		"dirb": True,
		"encryption": True,
		"entry": True,
		"header": True,
		"nikto": True,
		"whatweb": True,
		"wget": True,
	}
	
	# Set variables based on parsed values
	target = args.target
	port = args.port
	login["path"] = args.loginpath
	login["user"] = args.username
	login["password"] = args.password
	modifyBehaviour = args.modify
	if not args.runall:
		runTest["cookies"] = args.cookies
		runTest["comments"] = args.comments
		runTest["defaults"] = args.defaults
		runTest["dirb"] = args.dirb
		runTest["encryption"] = args.encryption
		runTest["entry"] = args.entry
		runTest["header"] = args.header
		runTest["nikto"] = args.nikto
		runTest["whatweb"] = args.whatweb
		runTest["wget"] = args.wget


# Various initialisation checks...
def initChecks():
	# Required declaration in order to modify later in the function
	global modifyBehaviour, runOrder, outputAllTests, outputReportName, port, target, target_full, wd
	runOrder = []
	outputAllTests = False
	outputReportName = "Findings-Report.txt"
	
	
	# Check that at least 1 module has been specified in the args
	try:
		if not any(value for value in runTest.values()):		# All modules are 'False', meaning none have been changed from default (so no args set)
			raise Exception("At least one test must be run. Use -all/--runall to run all modules.")
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
		
	
	# Ensure all login required information (all 3) has been entered
	try:
		# Non-entered arguments are stored as "None" - stop if any of the login dictionary keys have this value, but only if any of the keys have a value to begin with
		if any(value is not None for value in login.values()):
			if any(value is None for value in login.values()):
				raise Exception("Not all login information (path, user, and password) is present!")
			else:
				print("All login information present - PLEASE ENSURE THIS IS VALID BEFORE TESTS START!")
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	
	
	# Initalise wd (Working Directory) with the current working directory
	try:
		wd = os.getcwd() + "/SiteScan/"
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print(f"Working Directory is: {wd}")
		
	
	# Has the user chosen to modify normal functionality?
	try:
		if modifyBehaviour:
			# Since modification can still be skipped, use this to prevent incorrect outputs later on
			modifyBehaviour = False
			
			print("\n(You have chosen to modify script behaviour. Answer the following with yes or no...)")
			print("(A blank answer for any of the following indicates 'No'...)\n")
			
			# Using pyinputplus library, get yes/no response. Yes-type values return as "yes", No-type values return as "no", Blank as ""
			# There is seemingly no way to change this to return as boolean but using the input validaition library is still more elegant than self-made
			# The below if statement will set it to boolean though, as the library will only return "yes", "no", or "" (blank), only "yes" is considered True
			if (pyinputplus.inputYesNo("Should all modules run be output in the report, regardless of whether they have been specified in the initial args?: ", blank=True)) == "yes":
				outputAllTests = True
				modifyBehaviour = True
				
			if (pyinputplus.inputYesNo("Should files be saved into a different directory than current?: ", blank=True)) == "yes":
				wd = pyinputplus.inputStr("> Enter new FULL working directory (no spaces): ")
				modifyBehaviour = True
				if not wd.endswith("/"):	# Check if the directory is missing a forward-slash
					wd += "/"					# If yes, then add one
					
			if (pyinputplus.inputYesNo("Should the output report file name be changed?: ", blank=True)) == "yes":
				outputReportName = pyinputplus.inputStr("> Enter new filename ONLY to save to the working directory (no spaces): ")
				modifyBehaviour = True
			
			print("")	# Just a blank line for better output formatting
		
		# Will print a message if modifyBehaviour was never arg-specified, or if it had but no changes have been made
		if modifyBehaviour == False:
			print("Script behaviour not modified - Outputting only specified tests, and using current directory and standard report filename.")
			
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	
	
	# Check for dependencies - Do any specified tools require another to be run? (e.g. for file discovery and download services)
	try:
		keysRequired = ["dirb", "wget"]							# In this example, dirb and wget are required for the below modules
		keysToCheck = ["comments", "defaults", "entry"]			# What keys (modules) require those modules to be run before them in order to function?
		
		for keyCK in keysToCheck:									# Loop through all of those check keys, check if the test has been specified to run
			if runTest[keyCK]:										# If yes, make sure the required modules will run
				print(f"The following module(s) will be run first as a requirement: ", end="")
				for keyRQ in keysRequired:								# Loop through all the required keys now
					if runTest[keyRQ]:										# Firstly check if the module is going to be (specified to) run anyway
						outputAllTests = True									# If so, ensure that it will be output at the end
					else:													# If not, then make sure it will run
						runTest[keyRQ] = True
					print(f" '{keyRQ}'", end=",")							# Append the module name to the end of the print() above
					runOrder.append(keyRQ)								# Add the module to the end of the running order list
				print(f"")												# Finish the print appending
				break													# Stop checking other 'check keys'
		else:														# If none of the dependencies were specified at all though, the required keys might still have been specified
			for keyRQ in keysRequired:									# For each of the 'requirement keys', if it's specified, ensure it will be output in the report
				if runTest[keyRQ]:
					outputAllTests = True
			
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	
	
	# Check specified/required tools are executable through Path
	# (Ensure required commands are available, get the commandExists() function to raise an exception itself if not)
	try:
		if runTest["dirb"]:
			commandExists("dirb", False)
		if runTest["encryption"]:
			commandExists("curl", False)
			commandExists("sslscan", False)
		if runTest["nikto"]:
			commandExists("nikto", False)
		if runTest["whatweb"]:
			commandExists("whatweb", False)
		if runTest["wget"]:
			commandExists("wget", False)
			
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("All required tools are executable through Path.")
	
	
	# Set the run order for the modules (tests) - orders as the keys are declared in the dictionary (alphabetically)
	try:
		for test in runTest.keys():								# Loop through all the tests
			if runTest[test] and test not in runOrder:				# If the test is to be run AND it isn't already in the run order list
				runOrder.append(test)									# Add it to the end of the run order list
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print(f"Tests will execute in the order: {runOrder}")
		
	
	# Ensure given target is valid
	try:
		if isValidValue("url", target):			# URL is good, IPv4 not tested
			isURL = True
		elif isValidValue("ipv4", target):		# Otherwise, URL is bad, IPv4 is good
			isURL = False
		elif isValidValue("domain", target):	# Also check to see if the user has just entered a domain (URL without leading protocol) 
			isURL = False							# The "URL" check done means if it has a leading protocol
		else:								# Otherwise, URL, IPv4, and Domain are bad. Exit so user can retry
			raise Exception("Target is not a valid IPv4 or web address (HTTP:// URL)")
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:									# If either is good, this message will display
		print("Target appears of valid type and correctly formatted.")
	
	
	# Clean URL target, identify and store domain
	# ("cleaning" here means removing everything after the domain, leaving only the protocol and domain)
	if isURL:
		try:
			if (target.find("/", 8)) != -1:					# Find "/" after 8 characters (https://), .find() returns '-1' if not found
				selection = target.find("/", 8)					# Select everything after and including the first "/", searching after the first 8 characters
				target = target[:selection]						# Remove the selection using Python slicing notation

			if (target.find(":", 6)) != -1:					# The same but for ":" (port specifier), anywhere after the first 6 characters (https:)
				selection = target.find(":", 6)					# Again, set the selection index to the first occurrence of ":"
				target = target[:selection]						# Again, remove everything from that index position onwards
				
			if (target.find("?")) != -1:					# The same but for "?" (query parameters), anywhere in the target string
				target = target.split("?")[0]					# Remove everything after that first detected "?"
				
			if (target.find("#")) != -1:					# The same but for "#" (JavaScript ID)
				target = target.split("#")[0]					# Again, split the string upon the first "#", keep only the first part (index 0)
				
			target_full = target							# Copy the now "cleaned" target into target_full variable. Now reduce target to only the domain...
			target = target.split("://", 1)[1]				# Split at [first] "://", maximum of 1 split, keep only the second part (index 1)
		except Exception as errorMsg:
			print(f"\nAn error occurred: {errorMsg}")
			sys.exit()
		else:
			print("URL target cleaned and identified domain stored.")
	
	
	# Identify port to be used
	try:
		if port is None:																	# If port isn't specified using -arguments...
			if isURL:																			# If the target is a URL...
				if target_full.startswith("http"):
					print("No port specified, inferred 80 from HTTP protocol.")
					port = 80
				elif target_full.startswith("https"):
					print("No port specified, inferred 443 from HTTPS protocol.")
					port = 443
				else:																				# This should realistically never happen due to all the previous validation code!
					raise Exception("Target (target_full) doesn't start with HTTP(S)")
			else:																				# Otherwise, the target is an IP/Domain, just default to HTTP for ease and compatibility
				port = 80
				print(f"No port specified, defaulting to {port}.")
		else:																				# Otherwise, confirm that the specified port will be used (regardless of URL protocol)
			print(f"Port {port} specified (by startup args) to be used.")
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
		
	
	# Check for type misidentification (IP thought to be URL due to web protocol)
	try:
		if isURL:
			if isValidValue("ipv4", target):												# Test if the "URL" is actually a valid IP address
				print("(Target IP misidentified as URL, but IP is valid. Continuing...)")
				isURL = False
			elif not isValidValue("domain", target):										# Otherwise, test if the "URL" does not contain a domain (catches invalid IP)
				raise Exception("Target IP misidentified as URL, but IP is invalid anyway.")	# ... Invalid IPs, even in the URL, should generally be caught by the starting validation checks though
			#else:										
				#print("Target correctly identified as type URL.")							# Otherwise, its not IPv4 [but DOES contain a domain], so is fine (is a correct URL)
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	
			
	# Create a target_full for IP address or Domain, based on the port
	# (A beginning protocol for target is required by some tools, regardless of IP/URL - such as Dirb)
	try:
		if not isURL:											# We have confirmed it is a valid IP address (or Domain) by this stage
			if port == 80:
				target_full = "http://" + target
			elif port == 443:
				target_full = "https://" + target
			else:
				raise Exception("Invalid port supplied!")		# This should not happen due to above port ID check and defaulting, but is here just in case
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	
	
	# Test if target is live (using ping)	
	try:
		# Using check_output() over run() due to issue with not detecting errors, this is tidier than staying with run()
		subprocess.check_output(["ping", "-c" ,"4", target], timeout=10, stderr=subprocess.DEVNULL)
	except subprocess.TimeoutExpired as errorMsg:
		print(f"{target} took too long to reach or was unreachable.")
		print(f"Error message: {errorMsg}")
		sys.exit()
	except subprocess.CalledProcessError as errorMsg:
		print(f"\nAn error occurred while pinging '{target}'.")
		print(f"Error message: {errorMsg}")			# Using run() would return a more detailed message, but this was missing major errors like "destination host unreachable"
		# Since generic error message, I've included help statements below. Not worth changing subprocess to store as variable to check returncode (for IF statement) for 2 errors. 
		print("(Exit status 1 means no host reply or unreachable host)")
		print("(Exit status 2 indicates issues with the network or other lower-level problems)")
		sys.exit()
	else:
		print("Tested connection to target. Target is online.")
	
	
	# Test if application port is open on target
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(5)
	
	try:
		sock.connect((target, port))
	except Exception as errorMsg:
		print(f"\nAn error occurred connecting to '{target}' on port '{port}'.")
		print(f"Error message: {errorMsg}")
		sys.exit()
	else:
		print("Tested port connection. Port is open on target.")
	finally:
		sock.close()
		
		
	# Create required directories
	try:
		os.makedirs(wd, exist_ok=True)
		os.makedirs(wd + "data/", exist_ok=True)
		os.makedirs(wd + "data/raw/", exist_ok=True)
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print(f"Required directories created.\n\n")


# Run the site cookie usage module
def test_cookies():
	try:
		print("Cookies test starting...")
		
		writeToFile(outputFilePath, "Cookies Used", 3)
		writeToFile(outputFilePath, "(Using Python 'requests' library)", 4)
		
		# Create a 'requests' session object
		session = requests.Session()
		
		# Use login data entered in startup args, if that was done
		# Although this should be checked in initChecks(), be sure here too - check if at least 1 login value is present
		if any(value is not None for value in login.values()):
			URL = target_full + login["path"]					# Login path should have been entered as "/path/"
			loginData = {										# Create a dictionary for the data to be sent for login
				"username": login["user"],							# Use the entered login username on the form field "username"
				"email": login["user"],								# Also try the form field "email" in case that is used instead
				"password": login["password"],						# Use the entered login password on the form field "password"
				"login": "submit"									# The method for logging in will be the "submit" [button] 
			}
			response = session.post(URL, data=loginData)			# Log-in to the site
			session.cookies.update(response.cookies)				# Ensure any cookies from login are included in the below output
			writeToFile(outputFilePath, "(Supplied login data used for login attempt)\n", 2)
		else:
			writeToFile(outputFilePath, "(No login credentials supplied)\n", 2)
		
		response = session.get(target_full)						# Run a general GET request on the main page
		
		# If no cookies are in use, communicate that. Otherwise, display them.
		if len(session.cookies) == 0:
			writeToFile(outputFilePath, "\n(No cookies in use on the main site page)")
		else:
			# Define a list of standard cookie attributes to display (if they exist)
			cookieAttributes = ["domain", "path", "expires", "secure", "version"]
		
			for cookie in session.cookies:
				# Name and value are always present
				writeToFile(outputFilePath, "\nName: " + cookie.name + "\n")
				writeToFile(outputFilePath, "Value: " + cookie.value + "\n")
				
				# Display each cookie attribute in turn, if the attribute exists
				for attribute in cookieAttributes:
					attributeValue = getattr(cookie, attribute)
					if attributeValue:
						output = attribute.capitalize() + ": " + str(attributeValue) + "\n"
						writeToFile(outputFilePath, output)
			
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("Cookies test complete.\n")
	

# Run the code comments search module
def test_comments():
	try:
		print("Code Comments search starting...")
		
		# Define the comment-related strings to search for
		commentsToFind = ["//", "<!--", "-->", "/*", "*/"]
		
		# Define the related mistaken strings to skip 
		stringsToSkip = ["://", "-//"]				# Web protocol string, common DOCTYPE "-//W3C//" tag
		
		writeToFile(outputFilePath, "Code Comments", 3)
		writeToFile(outputFilePath, "Text search of downloaded files for: " + str(commentsToFind), 4)
		writeToFile(outputFilePath, "Ignoring strings with: " + str(stringsToSkip), 4)
		
		# Search all downloaded files for comment strings
		with open(downloadedFileListPath, "r") as listFile:			# Open the list of downloaded files
			for listLine in listFile:									# For each line, that is a file to search
				listLine = listLine.strip()								# Remove any leading/trailing white space
				filePath = wd + "data/" + target + listLine				# Transform relative path into full path
				with open(filePath, "r") as file:							# Open each file in turn
					lineNum = 0													# Keep track of what the current line number is
					stringFound = False											# Reset the string detected flag
					for line in file:											# For each line in the file...
						lineNum += 1												# Increment the line number each new line
						for string in commentsToFind:								# For each comment string to find...
							if string in line:											# If the current comment string is found in the line...
								for skipString in stringsToSkip:							# For each skip string to find...
									if skipString in line:										# If the skip string is found in the line...
										break														# Move on to the next comment string
								else:														# If there were no occurrences of the skip strings, all is good...
									line = line.strip()											# Remove leading/trailing white space
									stringPos = line.find(string)								# Find the position of the comment in the line
									lineComment = line[stringPos:(stringPos+150)]				# Take the 150 characters from that position, and use that as the output
									# If ther string doesn't have 150 characters, it'll just store everything up to the end of the line
									
								# Output: {file path} (Line x) >>> {150 characters from the start of the comment}
									output = listLine + " (Line " + str(lineNum) + ") >>> " + lineComment
									writeToFile(outputFilePath, output + "\n")
									stringFound = True
									break														# Once the comment string has been found, skip to the next line altogether (stops duplicates)
					if stringFound:												# If the string has been found, create a space between each file for readability formatting
						writeToFile(outputFilePath, "\n")
						stringFound = False											# Reset the string detected flag
								
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("Code Comments search complete.\n")	

		
# Run the default files search module
def test_defaults():
	try:
		print("Default Files search starting...")
		
		# Define the files to search for - Can be a specific path, or filename-only for global/recursive search
		exactStringsToFind = ["/robots.txt", "/sitemap.xml", "/humans.txt", "/license.txt", "/readme.html", "/.htaccess", "/.phpinfo.php"]
		stringsToFind = ["web.config", "crossdomain.xml"]
		
		writeToFile(outputFilePath, "Default Files", 3)
		writeToFile(outputFilePath, "Searching downloaded file list for exact: " + str(exactStringsToFind), 4)
		writeToFile(outputFilePath, "Also searching loosely for: " + str(stringsToFind), 4)
		
		# Open the list of downloaded files, search each line for occurrences of the files/filepaths of interest
		with open(downloadedFileListPath, "r") as file:
			for line in file:
				# Remove leading/trailing whitespace (such as newline characters)
				line = line.strip()
				# Search for full-line matches (for specific paths)
				for string in exactStringsToFind:
					if string == line:
						writeToFile(outputFilePath, "'" + string + "' found.\n")
				# Search for substring matches (for filenames or paths anywhere)
				for string in stringsToFind:
					if string in line:
						writeToFile(outputFilePath, "'" + string + "' found at '" + line + "'\n")
		
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("Default Files search complete.\n")

		
# Run the Dirb scan module	
def test_dirb():
	try:
		print("Dirb scan starting...")
		print("(Recursive search is on, this may take a little while)")
	
		# Use credentials if supplied
		credentials = ""
		if login["user"] is not None and login["password"] is not None:
			credentials = " -u " + login["user"] + ":" + login["password"]
		
		# Run the command and store the output. Run in silent mode and won't stop on warning messages
		command = "dirb " + target_full + " /usr/share/dirb/wordlists/common.txt" + " -S -w" + credentials
		output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
		
		# Write the raw output to the report file, if the module was specified in the startup args
		if outputAllTests:
			writeToFile(outputFilePath, "Dirb", 3)
			writeToFile(outputFilePath, command, 4)
			writeToFile(outputFilePath, output)
		
		# Also write to a raw file to be read back in next (causes out of range error otherwise), also create/overwrite dirb.txt
		rawOutputFilePath = wd + "data/raw/dirb_raw-output.txt"
		writeToFile(rawOutputFilePath, output, 1, "w")
		writeToFile(wd + "data/dirb.txt", "", 1, "w")
		
		# Identify and extract discovered paths, write them to a file
		with open(rawOutputFilePath, "r") as file:
			for line in file:									# Read in each line of the raw-output txt file
				line = line.strip()									# Remove trailing white space and newline characters
				if target not in line:								# If target doesn't exist in the string, then skip the line
					continue
				elif "---- Entering directory: " in line:			# Otherwise, if it contains this string, also skip the line (as it is technically a duplicate)
					continue
				else:												# Otherwise...
					# This code will extract the directories and filenames, allowing for spaces in names, multiple dots in filenames and paths, and various Dirb output formatting
					subLine = line[line.find(target) + len(target):]		# Extract everything from the end of the target to the end of the string, store that
					dotPos = subLine.rfind(".")								# Find the last occurrence of "." (dot) in the string, get its position
					if dotPos != -1:										# rfind() returns "-1" if not found, if it (the last dot) IS found then...
						slashPos = subLine.rfind("/", dotPos)					# Check that this isn't just a directory with a dot in the name... (Find last "/" after the "."--indexPos)
						if slashPos != -1:										# If it is then...
							dotPos = -1												# Type mis-identified. Set indexPos to get the 'type' re-identified later.
						else:													# If it is indeed a file extension we've identified, continue...
							subStr1 = subLine[:dotPos]								# Store the string between the start and that position (not including the dot)
							blankPos = subLine.find(" ", dotPos)					# Find the first occurrence of a space (" ") from that dot onwards
							if blankPos != -1:										# If that space is found then....
								subStr2 = subLine[dotPos:blankPos]						# Store everything from the dot to that space (not including the space)
								subStr = subStr1 + subStr2								# Combine the two strings into one, giving the full file path with extension
							else:													# If not, this is the end of the line (string)
								subStr2 = subLine[dotPos:]								# Store everything from the dot to the end of the string
								subStr = subStr1 + subStr2								# Combine the two strings into one, like above
					if dotPos == -1:										# If the string didn't contain a dot (or just needs re-identified)...
						slashPos = subLine.rfind("/")							# Search for the last occurrence of "/" in the string
						if slashPos != -1:										# If this is found then...
							subStr = subLine[:slashPos+1]							# Store the string between the start and that position (+ including that last "/")
						else:													# Otherwise, it may just be a file with no extension...
							blankPos = subLine.find(" ", slashPos)					# (Same code as previous for checking if ends with space or end of line)
							if blankPos != -1:
								subStr = subLine[slashPos:blankPos]						# Store from slash to the space (not including the space)
							else:
								subStr = subLine[slashPos:]								# Store from slash to the end of the line (string)

					# This code will write the extracted path to a file, it should have been identified and extracted above
					if subStr != "/":										# If for example line was "http://192.168.1.10/", subLine was just "/" so subStr was also "/", ignore it
						writeToFile(wd + "data/dirb.txt", subStr + "\n")
						
	except (subprocess.CalledProcessError, Exception) as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("List of relative files and directories found in '.data/dirb.txt'")
		print("Dirb scan complete.\n")


# Run the encryption analysis module		
def test_encryption():
	try:
		print("Encryption analysis starting...")
		
		writeToFile(outputFilePath, "Encryption Usage", 3)
		
		# Send a generic cURL get request to the server, run in silent mode (no progress meter or errors in output), and use grep to search the returned data for "Strict-Transport-Security"
		command = "curl " + target_full + " -s | grep -i Strict-Transport-Security"
		output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
		writeToFile(outputFilePath, "HSTS (HTTP Strict Transport Security) Policy", 4)
		writeToFile(outputFilePath, command, 4)
		if output == "":
			writeToFile(outputFilePath, "! HSTS not detected !\n\n\n\n")
		else:
			writeToFile(outputFilePath, "HSTS detected >>> ")
			writeToFile(outputFilePath, output + "\n\n\n\n")
			
		command = "sslscan --verbose --no-color " + target + ":" + str(port)
		output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
		writeToFile(outputFilePath, "SSL/TLS Certificates", 4)
		writeToFile(outputFilePath, command, 4)
		writeToFile(outputFilePath, output)
		
	except (subprocess.CalledProcessError, Exception) as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("Encryption analysis complete.\n")


# Run the entry point search module
def test_entry():
	try:
		print("Entry Points search starting...")
		
		# Search downloaded files for HTML Form Input tags
		writeToFile(outputFilePath, "Entry Points - HTML Form Inputs", 3)
		writeToFile(outputFilePath, "Text search of downloaded files", 4)

		with open(downloadedFileListPath, "r") as listFile:			# Open the list of downloaded files
			for listLine in listFile:									# For each line, that is a file to search
				listLine = listLine.strip()									# Remove any leading/trailing white space (such as newline characters)
				filePath = wd + "data/" + target + listLine					# Transform relative path into full path
				with open(filePath, "r") as file:							# Open each file in turn
					lineNum = 0													# Keep track of what the current line number is
					stringFound = False											# Reset the string detected flag
					for line in file:											# For each line in the file...
						lineNum += 1												# Increment the line number each new line
						if "<input " in line:										# If the string is found in the line...
							line = line.strip()											# Remove leading/trailing white space
							stringPos = line.find("<input ")							# Find the position of the comment in the line
							lineEntry = line[stringPos:(stringPos+150)]					# Take the 150 characters from that position, and use that as the output
							# If ther string doesn't have 150 characters, it'll just store everything up to the end of the line
							
							output = listLine + " (Line " + str(lineNum) + ") >>> " + lineEntry
							writeToFile(outputFilePath, output + "\n")			# Output the whole line to the report file
							stringFound = True
					if stringFound:												# If the string has been found, create a space between each file for readability formatting
						writeToFile(outputFilePath, "\n")
						stringFound = False											# Reset the string detected flag
		
		
		# Search downloaded file list for any files with query parameters ("?")
		writeToFile(outputFilePath, "Entry Points - Web Page Query Parameters", 3)
		writeToFile(outputFilePath, "Text search of downloaded files list for filenames containing '?'", 4)
		writeToFile(outputFilePath, "The following files have been observed to use query parameters: \n", 2)
		
		with open(downloadedFileListPath, "r") as file:
			for line in file:
				line = line.strip()
				if "?" in line:
					writeToFile(outputFilePath, line + "\n")
								
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("Entry Points search complete.\n")

	
# Run the HTTP header analysis module
def test_header():
	try:
		print("HTTP Header analysis starting...")
		
		writeToFile(outputFilePath, "HTTP Header", 3)
		writeToFile(outputFilePath, "(Using Python 'requests' library .get() function", 4)
		
		# Use the 'requests' library to send a get request, then display the returned HTTP headers each on a new line
		response = requests.get(target_full)
		for header in response.headers:
			writeToFile(outputFilePath, header + ": " + response.headers[header] + "\n")
		
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("HTTP Header analysis complete.\n")


# Run the Nikto scan module		
def test_nikto():
	try:
		print("Nikto scan starting...")
		print("(This may take a short while)")
		
		command = "nikto -h " + target_full
		output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
		
		writeToFile(outputFilePath, "Nikto", 3)
		writeToFile(outputFilePath, command, 4)
		writeToFile(outputFilePath, output)
		
	except (subprocess.CalledProcessError, Exception) as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("Nikto scan complete.\n")

	
# Run the WhatWeb scan module
def test_whatweb():
	try:
		print("WhatWeb test starting...")
		
		# Run standard WhatWeb command, but don't use colour formatting for output
		command = "whatweb " + target_full + " --color=never"
		output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
		
		# Split the output for better formatting
		outputSplit = output.split(", ")
		
		writeToFile(outputFilePath, "WhatWeb", 3)
		writeToFile(outputFilePath, command, 4)
		for outputLine in outputSplit:
			writeToFile(outputFilePath, outputLine + "\n")
		
	except (subprocess.CalledProcessError, Exception) as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("WhatWeb test complete.\n")

	
# Run the Wget spider scan and file download module
# Downloads all types of files. The -R reject option can be added to prevent download of certain files, such as multimedia.
# (For example "--reject=jpg,jpeg,png,gif,mp4,m4v,avi,mov,mpg,mpeg,wmv,flv,swf,mp3,wav,ogg,webm,webp,3gp")
def test_wget():
	try:
		print("Wget scan starting...")
		
		# Gets used by other dependent modules (see below notes)
		global downloadedFileListPath
		
		# Run a recursive (spider-like) download of files
		# (-No Verbose output, -Put it in a certain directory. Also it needs "2>&1", which redirects error messages to output also, in order to show anything)
		# The -R is used to reject any files with the ending "?C=", anywhere in the name (*). This parameter is used by Apache servers for "fancy indexing" (basically just sorting the index.html)
		# This is unnecessary but doesn't change the content of the index itself, just the order, so isn't useful and otherwise just causes bloat of the downloads
		command = "wget -r -nv " + target_full + " 2>&1 -P " + wd + "data/" + " -R '*\?C=*'"
		output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
		
		# Write the output to the report file, if the module was specified in the startup args
		if outputAllTests:
			writeToFile(outputFilePath, "Wget", 3)
			writeToFile(outputFilePath, command, 4)
			writeToFile(outputFilePath, output)
		
		# If a Dirb scan has been selected...
		# (That module being run prior to this one should be guaranteed by the running order and init checks)
		if runTest["dirb"]:
			print("Dirb scan run previously. Scanning directories in ./data/dirb.txt...")
			# Overwrite file only if it's newer than already-downloaded (-N), read in from list of files (-i), use the target as a base due to relative paths, do spider behaviour for these entries too (-r)
			command = "wget -r -nv -N -i " + wd + "data/dirb.txt --base " + target_full + " 2>&1 -P " + wd + "data/" + " -R '*\?C=*'"
			output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
			if outputAllTests:
				writeToFile(outputFilePath, "Wget - ./data/dirb.txt", 3)
				writeToFile(outputFilePath, command, 4)
				if output == "":														# If the output is blank, then Wget did not download/replace any new files
					writeToFile(outputFilePath, "(No new files downloaded)")
				else:
					writeToFile(outputFilePath, output)
		
		# If a robots.txt file has been downloaded, check there as well for anything interesting
		if os.path.exists(wd + "data/" + target + "/robots.txt"):
			print("Robots.txt file downloaded. Scanning those directories as well...")
			writeToFile(wd + "data/" + "/robots_path-only.txt", "", 1, "w")
			with open(wd + "data/" + target + "/robots.txt", "r") as file:
				for line in file:
					if "llow: " in line:													# Searches for the lines that contain "Disallow" or "Allow"
						disallowedPath = "/" + line.split("llow: ")[1].strip()				# Take anything after it, discarding any trailing white space and matching formatting of other path-only files like dirb.txt
						writeToFile(wd + "data/" + "/robots_path-only.txt", disallowedPath)
			command = "wget -r -nv -N -i " + wd + "data/robots_path-only.txt --base " + target_full + " 2>&1 -P " + wd + "data/" + " -R '*\?C=*'"
			output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
			if outputAllTests:
				writeToFile(outputFilePath, "Wget - robots.txt", 3)
				writeToFile(outputFilePath, command, 4)
				if output == "":
					writeToFile(outputFilePath, "(No new files downloaded)")
				else:
					writeToFile(outputFilePath, output)
			
		# Could add sitemap.xml etc. search in future as well, but this is good enough for now
		# Also could do with trying to download the default files specified in test_defaults(), such as phpinfo.php
		
		# Generate a recursive list of all relative file paths (for files, not directories) downloaded, checking recursively.
		# This file gets used by dependencies of this module, such as 'comments' analysis. This module should auto always be run before dependencies (see initChecks())
		downloadedFileListPath = listFiles(wd + "data/" + target)
		
	except (subprocess.CalledProcessError, Exception) as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("Wget scan(s) complete.\n")


		
		
# ~~~ FUNCTIONAL ~~~

# Check if a command is on PATH and marked as executable, with optional argument to return value or raise exception in case of failure (negative answer)
def commandExists(command, returnFail=True):
	try:
		if shutil.which(command) is not None:
			return True
		else:
			if returnFail:
				return False
			else:
				raise Exception(f"Command '{command}' does not exist or is not executable through Path")
				
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	

# Check if a value is valid (using 'validators' package)
def isValidValue(type, value):
	try:
		if type == "ipv4":
			if not validators.ipv4(value):
				# print(f"'{value}' is not a valid IPv4 address")
				return False
		elif type == "url":
			if not target.startswith("http"):
				# print(f"'{value}' is not the correct protocol")
				return False
				
			if not validators.url(value):
				# print(f"'{value}' is not a valid web URL")
				return False
		elif type == "domain":
			if not validators.domain(value):
				# print(f"'{value}' is not a valid web domain")
				return False
		else:
			raise Exception(f"Type '{type}' is not valid!")
			
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		return True

	
# Write given text to a given file, using styling and write/open mode if specified. Will write continuiously, so needs new line ("\n") given in "text" parameter
# Text style: 1 = Normal (Default), 2 = CAPS, 3 = Section Header, 4 = Section Sub-header
def writeToFile(filePath, text, textStyle=1, openMode="a"):
	try:
		textStyle = int(textStyle)								# Convert to integer, allows function call using "2" by accident instead of just 2.
		
		with open(filePath, openMode) as file:					# Open file in append mode (default) - Edit existing file or create a file if it doesnt exist
			if textStyle == 1:										# Normal plain text, as given, will convert ints to string automatically
				file.write(text)
			elif textStyle == 2:									# Otherwise, ensure it is a string then transform to uppercase
				file.write(str(text).upper())
			elif textStyle == 3:									# Otherwise, do section header styling. Ensure a string for concatenation
				file.write("\n\n\n\n\n\n")
				file.write("--=== " + str(text) + " ===--\n")
			elif textStyle == 4:									# Otherwise, do section sub-header styling.
				file.write("-= " + str(text) + " =-")
				file.write("\n\n")
			else:													# Otherwise, number is invalid. Non-numeric strings will just cause Exception (see above convert to Int)
				raise Exception("Text style specified is not valid!")
				
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()

		
# List the files (not directories) within a given directory. Options to disable recursive listing, give full file paths instead of relative, and specify MIME types. Returns the output file's path.
# By default, lists files with MIME type including "text" (text/plain, text/xml etc.) - anything ASCII/UTF-8 etc encoded, meaning it will skip multimedia and archive files which are text-editor-unreadable
# The mimeTypeStartsWith is a standard string list, which gets unpacked into the correct format for startswith() -- turns into " startswith("text", "image", "application") " etc 
def listFiles(startPath, recursive=True, relative=True, mimeTypeStartsWith=["text"]):
	try:
		# Ensure path supplied is a directory before continuing. This will also cause auto-exception if invalid path.
		if os.path.isfile(startPath):
			raise Exception("Path supplied points to a file, not a directory")
		
		# Create a filename by replacing the slashes with dashes. Also create this file, clear/overwrite any existing files.
		outputFileName = "dir-list_" + startPath.replace("/", "-") + ".txt"
		outputPath = wd + "data/" + outputFileName
		writeToFile(outputPath, "", 1, "w")

		# Create list of files
		mime = magic.Magic(mime=True)										# Used for the file type checking next
		for root, dirs, files in sorted(os.walk(startPath)):				# For all directories and files in the file path... (need to order alphabetically for output)
			if not recursive:													# If only checking the provided [starting] directory
				dirs.clear()														# Clear the other directories so it doesn't traverse through them
			for file in files:													# For each "file" (or directory) in the current directory...
				filePath = os.path.join(root, file)									# Set the full path of the file
				if os.path.isfile(filePath):										# If the file is actually a file (and not a directory or misc non-file object)...
					if mime.from_file(filePath).startswith((*mimeTypeStartsWith,)):		# If the file type starts with any of the supplied MIME types
						if relative:														# If the path is to be output as a relative path, rather than full
							filePath = os.path.relpath(filePath, startPath)						# Set the relative file path, instead of full path
						writeToFile(outputPath, "/" + filePath + "\n")						# Add a "/" to the beginning of the file, so that it matches the formatting of dirb.txt
	
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()
	else:
		print("'" + startPath + "/' directory files listed in dir-list txt file in './data/'")
		return outputPath
						

		
		
# ~~~ MAIN ~~~
if __name__ == "__main__":
	try:
		# Declare and initalise relevant variables
		global outputFilePath
		launchDateTime = datetime.datetime.now()

		print("\n~~ SiteScan ~~\n")
		
		# Startup initalisation tasks
		getArgs()
		initChecks()

		# Start countdown (allows user time to quickly read messages and change their mind)
		for i in range(15, 0, -1):							# Iterate from 10 down to 1 (excluding 0), stepping [down] by -1
			print(f"Starting tests in... {i}", end="\r")		# "\r" moves the cursor to the beginning of the line
			time.sleep(1)
			print("\033[K", end="\r")							# "\033[K" clears the current line in terminals/consoles

		# Output opening header to report file
		outputFilePath = wd + outputReportName
		writeToFile(outputFilePath, "~~~~~~~~~~ SiteScan Report ~~~~~~~~~~\n", 1, "w")
		writeToFile(outputFilePath, "Started at: " + launchDateTime.strftime("%Y-%m-%d %H:%M:%S") + "\n")
		writeToFile(outputFilePath, "Target: " + target + "\n")
		writeToFile(outputFilePath, "Port: " + str(port) + "\n\n")
		writeToFile(outputFilePath, "Modules run, in order: " + str(runOrder) + "\n")
		if login["path"] is not None:														# initChecks ensures login username and password are also present ('not None')
			writeToFile(outputFilePath, "\nLogin path: " + login["path"] + "\n")
			writeToFile(outputFilePath, "Login username: " + login["user"] + "\n")
			writeToFile(outputFilePath, "Login password: " + login["password"] + "\n")
		if modifyBehaviour:
			writeToFile(outputFilePath, "\n ! Normal behaviour has been modified ! \n")
			if outputAllTests:
				writeToFile(outputFilePath, "- All modules run included in report, regardless of if specified in the startup arguments. \n")
		else:
			writeToFile(outputFilePath, "\nOnly modules specified in the startup arguments are displayed in this report. '-all' emulates that behaviour. \n")
		writeToFile(outputFilePath, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

		# Run each test in order by calling the corresponding function
		for test in runOrder:
			eval("test_" + test + "()")

		# End of program
		writeToFile(outputFilePath, "\n\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
		print(f"\nOUTPUT REPORT FOUND AT: " + outputFilePath)
		sys.exit()
		
	except Exception as errorMsg:
		print(f"\nAn error occurred: {errorMsg}")
		sys.exit()