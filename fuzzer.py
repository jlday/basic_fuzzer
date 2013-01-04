####################################################################################
# fuzzer.py
# 		A very simple file format fuzzer for attacking lower quality software.
# Uses a simple random byte assignment algorithm to change each file.
####################################################################################
# Dependencies:
# 		- psutil python library (http://code.google.com/p/psutil/) 
# 		- WinDbg (http://msdn.microsoft.com/en-us/windows/hardware/gg463009.aspx)
# 		- GFlags (http://msdn.microsoft.com/en-us/windows/hardware/gg463009.aspx)
# 		- Radamsa (http://code.google.com/p/ouspg/wiki/Radamsa)
# 		- window_killer (https://github.com/jlday/window_killer)
# 		- triage (https://github.com/jlday/triage)
####################################################################################
# Additional Installation Notes:
# 		The following WinDbg Script needs to be placed in the same directory as
# the WinDbg executable.  It should be called "monitor.wds".
'''
* monitor.wds - run this script upon launching an executable, 
*      when a crash occurs a file named "crash_details.txt" 
*      is written with the output of !exploitable

sxr
sxd -c "!load msec.dll; .logopen crash_details.txt; .echo ********************************************************************************; !exploitable; .echo ********************************************************************************; r; .echo ********************************************************************************; u; .echo ********************************************************************************; k; .echo ********************************************************************************; q" -h av

'''
####################################################################################
# Usage:
Usage = '''
python fuzzer.py [options] [target application]
options:
	
-b [path to base directory]
	path to directory containing input files to be traced
	Default: "BaseFiles"
-o [path to output directory]
	path to directory where trace files should be written to
	Default: "Crashes"
-w [path to WinDbg/GFlags]
	path to the installation of WinDbg/GFlags
	Default: "WinDbg"
-p [path to Radamsa executable] 
	path to the radamsa executable that will be used to mutate files
	Default: "radamsa-0.3.exe"
-t [path to test file directory]
	path where test files are stored.  Each iteration of the fuzzer
	will create two copies of the fuzzed file, one to store in the output
	directory and one to test.  This avoids any changes to the test file 
	during testing that may be caused by auto save and sanitize features 
	in the target program.  This file is always deleted after every test.
	Default: "Tests"
-a [arguments]
	string representing additional arguements to be passed to the target
	application during each test.
	Default: ""
-i [report interval]
	number of test cases to report progress, progress only reported if -v 
	is also specified
	Default: 1000
-m [time in seconds]
	max amount of time to allow for each test case
	Default: 10 seconds
-s [spray percentage]
	percentage of file to change with random byte assignment.
	Default: 0.05 %
-c [cpu sample time]
	time delay used when calculating the CPU usage percentage.
	Default: 0.5
-d 
	Save crash details along with the crash files.  Normally these can
	be gained by triaging the crashes, but can be useful for browsing
	results before triaging.  Only used when not in JIT Debugger Mode
-r 
	Enable mutations using the Radamsa test case generator.
-j 
	JIT Debugger Mode.  This will not spawn a debugger attached to the 
	target process on each test case.  Instead it will set WinDbg to 
	the system Just In Time debugger and check to see if WinDbg has 
	been spawned after each test.
-g
	Do not use GFlags while fuzzing.
-k 
	Enable an embedded window_killer to attempt to automatically deal with 
	dialog boxes spawned by the program.  This window_killer is spawned
	for each instance of the target application that is spawned and only 
	deals with windows belonging to the target's PID
-e
	Uses the window_killer to attempt to close the main window of the 
	target application before killing the process.  This is used to 
	trigger any events that might occur upon closing the application 
	normally for process cleanup
-z 
	Attempt to unzip files and fuzz contents as well as fuzzing the files 
	themselves 
-v
	Verbose Mode, includes progress updates and error messages
-h 	
	Print the usage message and exit
'''
####################################################################################
# Imports:
import subprocess, os, time, random, sys, getopt, shutil, zipfile
import psutil
####################################################################################
# Global Variables:
baseFiles = []
baseDir = "BaseFiles"
outputDir = "Crashes"
WinDbgPath = "WinDbg"
TestDir = "Tests"
target_args = ""
crashTxt = "crash_details.txt"
radamsaPath = "radamsa-0.3.exe"
reportEvery = 1000
cpu_usage_sample = 0.5
max_time = 10
MutationRate = 0.05
target = None
save_crash_details = False
radamsa = False
jitDebugging = False
useGflags = True
kill_windows = False
close_main = False
fuzz_zipped = False
verbose = False
####################################################################################
# Functions:

# Takes a file string of the format "open('file.ext', 'r').read()" and
# converts it to a list, mutates a [MutationRate] percentage of bytes
# by asigning them random values and joins the list back into a string
# and returns that value
def mutate(BaseStream):
	global MutationRate
	BaseStream = list(BaseStream)
	numMutations = len(BaseStream) * (MutationRate / 100.0)
	count = 0
	while count < numMutations:
		BaseStream[random.randint(0, len(BaseStream) - 1)] = chr(random.randint(0, 255))
		count += 1
	return "".join(BaseStream)

# Picks a random value from the [baseFiles] list, returns that value.
def PickFile():
	global baseFiles
	return baseFiles[random.randint(0, len(baseFiles) - 1)]

# Checks if WinDbg has been launched at all.  If so, kills WinDbg
# and returns True, otherwise returns False.
# used when fuzzing with JIT Debugging.
def CheckWinDbg():
	for proc in psutil.process_iter():
		if proc.name == "windbg.exe":
			psutil.Process(proc.pid).kill()
			return True
	return False

# Sets WinDbg as the system Just In Time debugger	
def SetWinDbgJIT():
	global verbose
	global WinDbgPath
	
	if verbose:
		print "Initializing WinDbg..."
	subprocess.call(WinDbgPath + os.sep + "windbg.exe -IS")

# Enables GFlags for the given process, if no process is 
# given, then default is the global target process
def EnableGFlags(proc=None):
	global verbose
	global WinDbgPath
	global target
	
	if proc == None:
		proc = target[target.rfind("\\") + 1:]
	if verbose:
		print "Setting GFlags for " + proc
	subprocess.call(WinDbgPath + os.sep + "GFlags.exe /p /enable " + proc + " /full")

# Disables GFlags for the given process, if no process is
# given, then default is the global target process
def DisableGFlags(proc=None):
	global verbose
	global WinDbgPath
	global target
	
	if proc == None:
		proc = target[target.rfind("\\") + 1:]
	if verbose:
		print "Disabling GFlags for " + proc
	subprocess.call(WinDbgPath + os.sep + "GFlags.exe /p /disable " + proc)
	
# Initialize the base file set and the base file directory (if specified)
def InitBaseFiles(dir=None):
	global verbose
	global baseDir
	global baseFiles
	
	if dir != None:
		baseDir = dir
	if verbose:
		print "Initializing Base File List..."
	baseFiles = []
	for file in os.listdir(baseDir):
		baseFiles += [baseDir + os.sep + file]
	if verbose:
		print "Base Files Initialized:"
		for file in baseFiles:
			print file

# test the given file against the global [target] application
# file is deleted at the end of this funcition if no crash
# is found
def RunTest(file):
	global verbose
	global TestDir
	global outputDir
	global target_args
	global jitDebugging
	global target
	global max_time
	global save_crash_details
	global kill_windows
	global close_main
	global cpu_usage_sample
	
	proc = None
	debugger = None
	windowKiller = None
	
	if kill_windows or close_main:
		import window_killer
	
	try:
		if not os.path.exists(outputDir):
			os.path.mkdir(outputDir)
		
		if os.path.exists(crashTxt):
			os.remove(crashTxt)
			
		if not os.path.exists(TestDir):
			os.mkdir(TestDir)
			
		outputFile = file
		file = TestDir + os.sep + outputFile[outputFile.rfind(os.sep) + 1:]
		shutil.copy(outputFile, file)
		
		if jitDebugging:
			try:
				proc = psutil.Process(subprocess.Popen("\"" + target + "\" " + target_args + " \"" + file + "\"").pid)
				
				if kill_windows:
					windowKiller = window_killer.MultithreadedWindowKiller(proc.pid)
					windowKiller.start()
				
				timeout = 0
				while timeout < max_time and proc.get_cpu_percent(interval=cpu_usage_sample) > 1:
					timeout += 1 + cpu_usage_sample
					time.sleep(1)
				
				if not CheckWinDbg():
					try:
						if close_main: 
							window_killer.CloseMain(proc.pid)
					except:
						pass
					time.sleep(1)
					os.remove(file)
					os.remove(outputFile)
				else:
					if verbose:
						print "Crash Detected!!" 
						print "Saving crash file... " + file
			except KeyboardInterrupt:
				try:
					if proc != None and proc.status != psutil.STATUS_DEAD:
						proc.kill()
					os.remove(file)
					os.remove(outputFile)
				except:
					pass
				if windowKiller != None:
					windowKiller.start_halt()	
				raise KeyboardInterrupt()
			except:
				try:
					if proc != None and proc.status != psutil.STATUS_DEAD:
						proc.kill()
					os.remove(file)
					os.remove(outputFile)
				except:
					pass
		else:
			debugger = proc = psutil.Process(subprocess.Popen(WinDbgPath + os.sep + "windbg.exe -Q -c \"$$<" + WinDbgPath + os.sep + "monitor.wds; g;\" -o \"" + target + "\" " + target_args + " \"" + file + "\"").pid)
			time.sleep(1)
			timeout = 0
			while timeout < 3:
				for p in psutil.process_iter():
					if p.name.lower() == target[target.rfind(os.sep) + 1:].lower():
						proc = p
						break
				if proc.name.lower() == target[target.rfind(os.sep) + 1:].lower():
					break
				time.sleep(1)
				timeout += 1
			
			if kill_windows:
				windowKiller = window_killer.MultithreadedWindowKiller(proc.pid)
				windowKiller.start()
			
			timeout = 0
			try:
				while proc.status != psutil.STATUS_DEAD and proc.get_cpu_percent(interval=cpu_usage_sample) > 1 and timeout < max_time:
					time.sleep(1)
					timeout += 1 + cpu_usage_sample
				if proc != None and proc.status != psutil.STATUS_DEAD:
					if close_main:
						window_killer.CloseMain(proc.pid)
				if debugger != None and debugger.status != psutil.STATUS_DEAD:
					debugger.kill()
			except KeyboardInterrupt:
				try:
					if proc != None and proc.status != psutil.STATUS_DEAD:
						proc.kill()
					if debugger != None and debugger.status != psutil.STATUS_DEAD:
						debugger.kill()
					os.remove(file)
					os.remove(outputFile)
				except:
					pass
				if windowKiller != None:
					windowKiller.start_halt()
				raise KeyboardInterrupt()
			except:
				pass
			if os.path.exists(crashTxt):
				if verbose:
					print "Crash Detected!!"
					print "Saving crash file... " + file
				if save_crash_details:
					details = outputFile + "-details.txt"
					shutil.move(crashTxt, details)
					import triage
					triage.outputDir = outputDir
					triage.ProcessDetailsFile(details, outputFile)
				else:
					os.remove(crashTxt)
			else:
				os.remove(file)
				os.remove(outputFile)
	except KeyboardInterrupt:
		if windowKiller != None:
			windowKiller.start_halt()
		while os.path.exists(file):
			try:
				os.remove(file)
			except:
				pass
		raise KeyboardInterrupt()
	except:
		pass
	while os.path.exists(file):
		try:
			os.remove(file)
		except:
			pass
	if windowKiller != None:
		windowKiller.start_halt()

# Generates a unique name to be used as an output file name + path for newly fuzzed files		
def GenerateTestFileName(basename):
	testFile = outputDir + os.sep + basename[basename.rfind("\\") + 1:basename.rfind(".")] + ("-0x%0.8X" % random.randint(0, 0xFFFFFFFF)) + basename[basename.rfind("."):]
	while testFile == None or os.path.exists(testFile):
		testFile = outputDir + os.sep + basename[basename.rfind("\\") + 1:basename.rfind(".")] + ("-0x%0.8X" % random.randint(0, 0xFFFFFFFF)) + basename[basename.rfind("."):]
	return testFile
		
# The main fuzzer loop
# Responsable for enabling and disabling GFlags and WinDbg as JIT debugger
def RunFuzzer():	
	global baseFiles
	global outputDir
	global TestDir
	global reportEvery
	global useGflags
	global radamsaPath
	global radamsa
	global fuzz_zipped
	global verbose
	
	testFile = None
	count = 1
	
	try:
		if useGflags:
			EnableGFlags()
		if jitDebugging:
			SetWinDbgJIT()
		
		if verbose:
			print "Starting Fuzzer..."
		
		if not os.path.exists(outputDir):
			os.mkdir(outputDir)
		
		if not os.path.exists(TestDir):
			os.mkdir(TestDir)
		
		while True:
			if verbose and ((reportEvery > 1 and count % reportEvery == 1) or (reportEvery == 1 and count % reportEvery == 0)):
				print "Working on file #" + str(count) 
			file = PickFile()
			testFile = GenerateTestFileName(file)
			if radamsa:
				subprocess.call(radamsaPath + " -o " + testFile + " " + file)
			else:
				open(testFile, "wb").write(mutate(open(file, "rb").read()))
			RunTest(testFile)
			count += 1
			
			# Process zipped files
			if fuzz_zipped and zipfile.is_zipfile(file):
				archive = zipfile.ZipFile(file, "r")
				for subfile in archive.namelist():
					testFile = GenerateTestFileName(file)
					if verbose and ((reportEvery > 1 and count % reportEvery == 1) or (reportEvery == 1 and count % reportEvery == 0)):
						print "Working on file #" + str(count)
					tempFile = TestDir + os.sep + "temp.tmp"
					if radamsa:
						open(tempFile, "wb").write(archive.read(subfile))
						tempFileOut = tempFile[:tempFile.rfind('.')] + "2" + tempFile[tempFile.rfind('.') + 1:]
						subprocess.call(radamsaPath + " -o " + tempFileOut + " " + tempFile)
						shutil.move(tempFileOut, tempFile)
					else:
						open(tempFile, "wb").write(mutate(archive.read(subfile)))
					
					test = zipfile.ZipFile(testFile, "w")
					for item in archive.namelist():
						if item != subfile:
							buffer = archive.read(item)
							test.writestr(item, buffer)
						else:
							test.write(tempFile, subfile, zipfile.ZIP_DEFLATED)
					test.close()
					os.remove(tempFile)
					RunTest(testFile)
					count += 1
				archive.close()	
	except KeyboardInterrupt:
		if useGflags:
			DisableGFlags()
		if testFile != None and os.path.exists(testFile):
			os.remove(testFile)
		if save_crash_details:
			import triage
			triage.CleanupFiles(outputDir)
		raise KeyboardInterrupt()	
		
# Prints the command line usage if run as stand alone application.
def PrintUsage():
	global Usage
	print Usage
####################################################################################
# Main:	
def main(args):
	global baseDir
	global outputDir
	global WinDbgPath 
	global radamsaPath
	global TestDir
	global target_args
	global reportEvery 
	global cpu_usage_sample
	global max_time 
	global MutationRate 
	global target
	global save_crash_details
	global radamsa
	global jitDebugging 
	global useGflags 
	global kill_windows
	global close_main
	global fuzz_zipped
	global verbose 
	
	if len(args) < 2:
		PrintUsage()
		exit()
	
	optlist, argv = getopt.getopt(args[1:], 'b:o:w:p:t:a:i:m:s:c:drjgkezvh')
	for opt in optlist:
		if opt[0] == '-b':
			baseDir = opt[1]
		elif opt[0] == '-o':
			outputDir = opt[1]
		elif opt[0] == '-w':
			WinDbgPath = opt[1]
		elif opt[0] == '-p':
			radamsaPath = opt[1]
		elif opt[0] == '-t':
			TestDir = opt[1]
		elif opt[0] == '-a':
			target_args = opt[1]
		elif opt[0] == '-i':
			reportEvery = int(opt[1])
		elif opt[0] == '-m':
			max_time = int(opt[1])
		elif opt[0] == '-s':
			MutationRate = float(opt[1])
		elif opt[0] == '-c':
			cpu_usage_sample = float(opt[1])
		elif opt[0] == '-d':
			save_crash_details = True
		elif opt[0] == '-r':
			radamsa = True
		elif opt[0] == '-j':
			jitDebugging = True
		elif opt[0] == '-g':
			useGflags = False
		elif opt[0] == '-k':
			kill_windows = True
		elif opt[0] == '-e':
			close_main = True
		elif opt[0] == '-z':
			fuzz_zipped = True
		elif opt[0] == '-v':
			verbose = True
		elif opt[0] == '-h':
			PrintUsage()
			exit()

	if len(argv) < 1:
		PrintUsage()
		exit()
	target = argv[0]
	
	try:
		InitBaseFiles()
		RunFuzzer()
	except KeyboardInterrupt:
		print "Ctrl-C Detected - Ending Fuzzing Session..."
####################################################################################
if __name__=="__main__":
	main(sys.argv)
####################################################################################	