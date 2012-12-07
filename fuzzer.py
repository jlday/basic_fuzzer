####################################################################################
# fuzzer.py
# 		A very simple file format fuzzer for attacking lower quality software.
# Uses a simple random byte assignment algorithm to change each file.
####################################################################################
# Dependencies:
# 		- psutil python library (http://code.google.com/p/psutil/) 
# 		- WinDbg (http://msdn.microsoft.com/en-us/windows/hardware/gg463009.aspx)
# 		- GFlags (http://msdn.microsoft.com/en-us/windows/hardware/gg463009.aspx)
# 		- window_killer python library
####################################################################################
# Additional Installation Notes:
# 		The following WinDbg Script needs to be placed in the same directory as
# the WinDbg executable.  It should be called "monitor.wds".
'''
* monitor.wds - run this script upon launching an executable, 
*      when a crash occurs a file named "crashDetector.txt" 
*      is written to the local directory.  There should be 
*      no contents in this file, the presence only indicates
*      that a crash was found.

sxr
sxd -c ".logopen crashDetector.txt; .logclose; q" -h av
sxi asrt
sxi aph
sxi bpe
sxi eh
sxi clr 
sxi clrn
sxi cce
sxd -c ".logopen crashDetector.txt; .logclose; q" -h dm
sxd -c ".logopen crashDetector.txt; .logclose; q" -h gp
sxd -c ".logopen crashDetector.txt; .logclose; q" -h ii
sxd -c ".logopen crashDetector.txt; .logclose; q" -h ip
sxd -c ".logopen crashDetector.txt; .logclose; q" -h dz
sxd -c ".logopen crashDetector.txt; .logclose; q" -h iov
sxd -c ".logopen crashDetector.txt; .logclose; q" -h ch
sxd -c ".logopen crashDetector.txt; .logclose; q" -h isc
sxi 3c
sxi svh
sxi sse
sxd -c ".logopen crashDetector.txt; .logclose; q" -h sbo
sxd -c ".logopen crashDetector.txt; .logclose; q" -h sov
sxi vs
sxd -c ".logopen crashDetector.txt; .logclose; q" -h wkd
sxi wob
sxi wos

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
	Default: "pintool"
-r [report interval]
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
-v
	Verbose Mode, includes progress updates and error messages
-h 	
	Print the usage message and exit
'''
####################################################################################
# Imports:
import subprocess, os, time, random, sys, getopt, shutil
import psutil
####################################################################################
# Global Variables:
baseFiles = []
baseDir = "BaseFiles"
outputDir = "Crashes"
WinDbgPath = "WinDbg"
crashTxt = "crashDetector.txt"
reportEvery = 1000
cpu_usage_sample = 0.5
max_time = 10
MutationRate = 0.05
target = None
jitDebugging = False
useGflags = True
kill_windows = False
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
	global outputDir
	global jitDebugging
	global target
	global max_time
	global kill_windows
	global cpu_usage_sample
	
	proc = None
	debugger = None
	windowKiller = None
	
	if kill_windows:
		import window_killer
	
	try:
		if not os.path.exists(outputDir):
			os.path.mkdir(outputDir)
		
		if os.path.exists(crashTxt):
			os.remove(crashTxt)
		
		if jitDebugging:
			try:
				proc = psutil.Process(subprocess.Popen("\"" + target + "\" \"" + file + "\"").pid)
				
				if kill_windows:
					windowKiller = window_killer.MultithreadedWindowKiller(proc.pid)
					windowKiller.start()
				
				timeout = 0
				while timeout < max_time and proc.get_cpu_percent(interval=cpu_usage_sample) > 1:
					timeout += 1 + cpu_usage_sample
					time.sleep(1)
				
				if not CheckWinDbg():
					try:
						proc.kill()
					except:
						pass
					time.sleep(1)
					os.remove(file)
				else:
					if verbose:
						print "Crash Detected!!" 
						print "Saving crash file... " + file
			except KeyboardInterrupt:
				try:
					if proc != None and proc.status != psutil.STATUS_DEAD:
						proc.kill()
					os.remove(file)
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
				except:
					pass
		else:
			debugger = proc = psutil.Process(subprocess.Popen(WinDbgPath + os.sep + "windbg.exe -Q -c \"$$<" + WinDbgPath + os.sep + "monitor.wds; g;\" -o \"" + target + "\" \"" + file + "\"").pid)
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
					proc.kill()
				if debugger != None and debugger.status != psutil.STATUS_DEAD:
					debugger.kill()
			except KeyboardInterrupt:
				try:
					if proc != None and proc.status != psutil.STATUS_DEAD:
						proc.kill()
					if debugger != None and debugger.status != psutil.STATUS_DEAD:
						debugger.kill()
					os.remove(file)
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
				os.remove(crashTxt)
			else:
				os.remove(file)
	except KeyboardInterrupt:
		if windowKiller != None:
			windowKiller.start_halt()
		raise KeyboardInterrupt()
	except:
		pass
	if windowKiller != None:
		windowKiller.start_halt()
		
# The main fuzzer loop
# Responsable for enabling and disabling GFlags and WinDbg as JIT debugger
def RunFuzzer():	
	global baseFiles
	global reportEvery
	global useGflags
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
		
		while True:
			if verbose and ((reportEvery > 1 and count % reportEvery == 1) or (reportEvery == 1 and count % reportEvery == 0)):
				print "Working on file #" + str(count) 
			file = PickFile()
			testFile = outputDir + os.sep + file[file.rfind("\\") + 1:file.rfind(".")] + ("-0x%0.8X" % random.randint(0, 0xFFFFFFFF)) + file[file.rfind("."):]
			while testFile == None or os.path.exists(testFile):
				testFile = outputDir + os.sep + file[file.rfind("\\") + 1:file.rfind(".")] + ("-0x%0.8X" % random.randint(0, 0xFFFFFFFF)) + file[file.rfind("."):]
			open(testFile, "wb").write(mutate(open(file, "rb").read()))
			RunTest(testFile)
			count += 1
	except KeyboardInterrupt:
		if useGflags:
			DisableGFlags()
		if testFile != None and os.path.exists(testFile):
			os.remove(testFile)
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
	global reportEvery 
	global cpu_usage_sample
	global max_time 
	global MutationRate 
	global target
	global jitDebugging 
	global useGflags 
	global kill_windows
	global verbose 
	
	if len(args) < 2:
		PrintUsage()
		exit()
	
	optlist, argv = getopt.getopt(args[1:], 'b:o:w:r:m:s:c:jgkvh')
	for opt in optlist:
		if opt[0] == '-b':
			baseDir = opt[1]
		elif opt[0] == '-o':
			outputDir = opt[1]
		elif opt[0] == '-w':
			WinDbgPath = opt[1]
		elif opt[0] == '-r':
			reportEvery = int(opt[1])
		elif opt[0] == '-m':
			max_time = int(opt[1])
		elif opt[0] == '-s':
			MutationRate = float(opt[1])
		elif opt[0] == '-c':
			cpu_usage_sample = float(opt[1])
		elif opt[0] == '-j':
			jitDebugging = True
		elif opt[0] == '-g':
			useGflags = False
		elif opt[0] == '-k':
			kill_windows = True
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