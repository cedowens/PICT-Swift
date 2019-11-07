import Cocoa
import Foundation
import Darwin
import SQLite3
import CoreFoundation
import OSAKit



//-----NEED TO GIVE YOUR MACH-O BINARY HARD DISK ACCESS IN ORDER FOR IT TO READ FROM SOME FILES, SUCH AS SAFARI.DB:
//steps:
//1. Open System Preferences -> Security & Privacy
//2. Click the Privacy tab
//3. on the Left panel, scroll down and select "Full Disk Access"
//4. Click the "+" button and then add the pict-Swift mach-o binary you built from the Swift code

//-----SECONDLY:
//***Ensure all browsers are closed so that there are no issues reading from the history databases


//note: I lifted this function named uptime directly from: https://www.kittell.net/code/swift-system-uptime/
func uptime() -> time_t {
        var boottime = timeval()
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        var size = MemoryLayout<timeval>.stride
         
        var now = time_t()
        var uptime: time_t = -1
         
        time(&now)
        if (sysctl(&mib, 2, &boottime, &size, nil, 0) != -1 && boottime.tv_sec != 0) {
            uptime = now - boottime.tv_sec
        }
        return uptime
    }
    
//note: I lifted this function named PrintSecondsToHumanReadable directly from: https://www.kittell.net/code/swift-system-uptime/
func PrintSecondsToHumanReadable (seconds:Int) -> String  {
        let sDays = String((seconds / 86400)) + " days"
        let sHours = String((seconds % 86400) / 3600) + " hours"
        let sMinutes = String((seconds % 3600) / 60) + " minutes"
        let sSeconds = String((seconds % 3600) % 60) + " seconds"
         
        var sHumanReadable = ""
         
        if ((seconds / 86400) > 0)
        {
            sHumanReadable = sDays + ", " + sHours + ", " + sMinutes + ", " + sSeconds
        }
        else if (((seconds % 86400) / 3600) > 0)
        {
            sHumanReadable = sHours + ", " + sMinutes + ", " + sSeconds
        }
        else if (((seconds % 3600) / 60) > 0)
        {
            sHumanReadable = sMinutes + ", " + sSeconds
        }
        else if (((seconds % 3600) % 60) > 0)
        {
            sHumanReadable = sSeconds
        }
        return sHumanReadable
    }

//------------------------------------------------------------------------------------------------------------------------------------------------
//Collector Settings - change to anything other than a string of "true" to skip that collector

var fileCollectorInfo = "true" //gathers stat flags on files in the /Users/<user> directories and sub directories as well as in /tmp
var persistCollectorInfo = "true"  //gathers info on persistence
var suspiciousCollectorInfo = "true" //looks for suspicious indicators in processes, plists, launch agents, etc.
var browserCollectorInfo = "true"  //collects browser extension data
var browserHistCollectorInfo = "true"  //collects browser history data
var bashConfigCollectorInfo = "true" //collects bash config data
var bashHistCollectorInfo = "true"  //collects bash history data
var processCollectorInfo = "true"  //collects running process data
var networkCollectorInfo = "true"  //collects network config data
var profileCollectorInfo = "true"  //collects profile info
var certsCollectorInfo = "true"  //collects cert info
var installationCollectorInfo = "true" //enumerates installations
var keepLSDataSettings = "true" //lsregister collection info
var zipItSettings = "true"  //zip all artifacts/files
var logCollectorInfo = "true"  //collects log artifacts
var logArgTime = "--last 12h" //WARNING: collecting unified logs without arguments or using a very wide time range will results in a very large amount of data!!
var shouldListApps = "true"
//------------------------------------------------------------------------------------------------------------------------------------------------
//Global variables edited later in code:
var hiddenString = ""
var nm1 = ""
var nm2 = ""
var nm3 = ""
var nm4 = ""
var dateResult = Date()
var dateResult2 = Date()
var dFormatter2 = ""
var visitDate = ""
var dateResult3 = Date()
var formatter2 = ""
var histURL = ""
var dResult4 = ""
var cVisitDate = ""
var cUrl = ""
var cTitle = ""
var cCount = ""
var ffoxDate = ""
var ffoxURL = ""

//---------initDestination----------//
var hostName = Host.current().names
let hName = ProcessInfo.processInfo.hostName
let date1 : DateFormatter = DateFormatter()
date1.dateFormat = "yyyy-MM-dd"
let date2 = Date()
let dString = date1.string(from: date2) //date string
let collectionFolderName = "PICT-\(hName)-\(dString)" //pict folder name

var collectPathURL = URL(fileURLWithPath: "\(collectionFolderName)")

let fileMan = FileManager.default

if !(fileMan.fileExists(atPath: collectionFolderName)){ //create the collection path if it doesn't exist
    try fileMan.createDirectory(at: collectPathURL, withIntermediateDirectories: true, attributes: nil)

}

//---------Collect-------------//
if geteuid() != 0 {
    print("Without root permissions, some operations will fail. Run again with root for more complete collection.")
    
    var bashDataFromRoot = "bash_collector_data2.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(bashDataFromRoot)", contents: nil, attributes: nil)
    let bashDataFromRootURL = URL(fileURLWithPath: "\(collectionFolderName)/\(bashDataFromRoot)")
    let bashDataFromRootFileHandle = try FileHandle(forWritingTo: bashDataFromRootURL)
    
    if (fileMan.fileExists(atPath: "/etc/profile")){
        bashDataFromRootFileHandle.write("/etc/profile data:\r----------------------------\r".data(using: .utf8)!)
        let rData = try String(contentsOfFile: "/etc/profile")
        bashDataFromRootFileHandle.write(rData.data(using: .utf8)!)
        bashDataFromRootFileHandle.write("\r".data(using: .utf8)!)
        }
    
    if (fileMan.fileExists(atPath: "/etc/bashrc")){
    bashDataFromRootFileHandle.write("/etc/bashrc data:\r----------------------------\r".data(using: .utf8)!)
    let rData2 = try String(contentsOfFile: "/etc/bashrc")
    bashDataFromRootFileHandle.write(rData2.data(using: .utf8)!)
    bashDataFromRootFileHandle.write("\r".data(using: .utf8)!)
    }
}
else {
    var bashDataFromRoot = "bash_collector_data2.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(bashDataFromRoot)", contents: nil, attributes: nil)
    let bashDataFromRootURL = URL(fileURLWithPath: "\(collectionFolderName)/\(bashDataFromRoot)")
    let bashDataFromRootFileHandle = try FileHandle(forWritingTo: bashDataFromRootURL)
    
    if (fileMan.fileExists(atPath: "/etc/profile")){
        bashDataFromRootFileHandle.write("/etc/profile data:\r----------------------------\r".data(using: .utf8)!)
        let rData = try String(contentsOfFile: "/etc/profile")
        bashDataFromRootFileHandle.write(rData.data(using: .utf8)!)
        bashDataFromRootFileHandle.write("\r".data(using: .utf8)!)
        }
    
    if (fileMan.fileExists(atPath: "/etc/bashrc")){
    bashDataFromRootFileHandle.write("/etc/bashrc data:\r----------------------------\r".data(using: .utf8)!)
    let rData2 = try String(contentsOfFile: "/etc/bashrc")
    bashDataFromRootFileHandle.write(rData2.data(using: .utf8)!)
    bashDataFromRootFileHandle.write("\r".data(using: .utf8)!)
    }
    
    if (fileMan.fileExists(atPath: "/etc/sudoers")){
    bashDataFromRootFileHandle.write("/etc/sudoers data:\r----------------------------\r".data(using: .utf8)!)
    let rData3 = try String(contentsOfFile: "/etc/sudoers")
    bashDataFromRootFileHandle.write(rData3.data(using: .utf8)!)
    bashDataFromRootFileHandle.write("\r".data(using: .utf8)!)
    }
    
}
    
let date3 : DateFormatter = DateFormatter()
date3.dateFormat = "dd MMMM YYYY @ HH:MM:SS"
date3.timeZone = TimeZone.current
let date4 = Date()
let dString2 = date3.string(from: date4)
print("Beginning PICT collection \(dString2)")
var startTime : CFAbsoluteTime = CFAbsoluteTimeGetCurrent()


//here is start of basics.py collector
print("Collecting basic machine info")
var basicsFilename = "basic_info.txt"
fileMan.createFile(atPath: "\(collectionFolderName)/\(basicsFilename)", contents: nil, attributes: nil)
let username = NSUserName()

let date5 : DateFormatter = DateFormatter()
date5.dateFormat = "dd MMMM YYYY @ HH:MM:SS"
let date6 = Date()

date5.timeZone = TimeZone(identifier: "UTC")
let dString3 = date5.string(from: date6) + " UTC"//curr UTC date val to use

let dateLocal : DateFormatter = DateFormatter()
dateLocal.dateFormat = "dd MMMM YYYY @ HH:MM:SS"
dateLocal.timeZone = TimeZone.current
let date7 = Date()
let dateLocalString = dateLocal.string(from: date7)//curr local date val to use

let basicsFileURL = URL(fileURLWithPath: "\(collectionFolderName)/\(basicsFilename)")

let basicsFileHandle = try FileHandle(forWritingTo: basicsFileURL)

basicsFileHandle.write("Collected by user \(username) on \(dString3) (local: \(dateLocalString))\r\r".data(using: .utf8)!)

var uptimeVal = PrintSecondsToHumanReadable(seconds: uptime())
basicsFileHandle.write("Uptime: \(uptimeVal)\r\r".data(using: .utf8)!)
basicsFileHandle.write("Hostname(s):\r".data(using: .utf8)!)
for name in hostName{
    basicsFileHandle.write(name.data(using: .utf8)!)
    basicsFileHandle.write("\r".data(using: .utf8)!)
}
basicsFileHandle.write("\r".data(using: .utf8)!)

let task = Process()
task.launchPath = "/usr/sbin/spctl" //need to see if this is same on Catalina
let args : [String] = ["--status"]
task.arguments = args
let pipe = Pipe()
task.standardOutput = pipe
task.launch()
let results = pipe.fileHandleForReading.readDataToEndOfFile()
let out = String(data: results, encoding: String.Encoding.utf8)!

if !(out.contains("assessments enabled")) {
    basicsFileHandle.write("[-] Gatekeeper is disabled!!\r\r".data(using: .utf8)!)
} else{
    basicsFileHandle.write("[+] Gatekeeper is enabled!!\r\r".data(using: .utf8)!)
}

let task2 = Process()
task2.launchPath = "/usr/bin/csrutil"
let args2 : [String] = ["status"]
task2.arguments = args2
let pipe2 = Pipe()
task2.standardOutput = pipe2
task2.launch()
let results2 = pipe2.fileHandleForReading.readDataToEndOfFile()
let out2 = String(data: results2, encoding: String.Encoding.utf8)!
basicsFileHandle.write(out2.data(using: .utf8)!)
basicsFileHandle.write("\r".data(using: .utf8)!)

let task3 = Process()
task3.launchPath = "/usr/bin/defaults"
let args3 : [String] = ["read", "/Library/Preferences/com.apple.alf", "globalstate"]
task3.arguments = args3
let pipe3 = Pipe()
task3.standardOutput = pipe3
task3.launch()
let results3 = pipe3.fileHandleForReading.readDataToEndOfFile()
let out3 = String(data: results3, encoding: String.Encoding.utf8)!

if out3.contains("0"){
    basicsFileHandle.write("[-] Application firewall is not enabled".data(using: .utf8)!)
    basicsFileHandle.write("\r\r".data(using: .utf8)!)
}
else {
    basicsFileHandle.write("[+] Application firewall is enabled".data(using: .utf8)!)
    basicsFileHandle.write("\r\r".data(using: .utf8)!)
    
}

if (fileMan.fileExists(atPath: "/private/etc/kcpassword")){
    basicsFileHandle.write("[-] WARNING! Automatic login is enabled by the user!\r".data(using: .utf8)!)
}

let task4 = Process()
task4.launchPath = "/usr/sbin/system_profiler"
let args4 : [String] = ["SPSoftwareDataType"]
task4.arguments = args4
let pipe4 = Pipe()
task4.standardOutput = pipe4
task4.launch()
let results4 = pipe4.fileHandleForReading.readDataToEndOfFile()
let out4 = String(data: results4, encoding: String.Encoding.utf8)!
basicsFileHandle.write("[+] Software Data:\r----------------------------\r".data(using: .utf8)!)
basicsFileHandle.write("\(out4)".data(using: .utf8)!)


let task5 = Process()
task5.launchPath = "/usr/sbin/system_profiler"
let args5 : [String] = ["SPHardwareDataType"]
task5.arguments = args5
let pipe5 = Pipe()
task5.standardOutput = pipe5
task5.launch()
let results5 = pipe5.fileHandleForReading.readDataToEndOfFile()
let out5 = String(data: results5, encoding: String.Encoding.utf8)!
basicsFileHandle.write("[+] Hardware Data:\r----------------------------\r".data(using: .utf8)!)
basicsFileHandle.write("\(out5)".data(using: .utf8)!)

let task6 = Process()
task6.launchPath = "/usr/bin/dscl"
let args6 : [String] = [".", "list", "/Users"]
task6.arguments = args6
let pipe6 = Pipe()
task6.standardOutput = pipe6
task6.launch()
let results6 = pipe6.fileHandleForReading.readDataToEndOfFile()
let out6 = String(data: results6, encoding: String.Encoding.utf8)!
var namesList = out6.components(separatedBy: "\n")

basicsFileHandle.write("[+] User data:\r----------------------------\r".data(using: .utf8)!)

for user in namesList {
    
    if user.prefix(1) != "_" && user != "daemon" && user != "nobody" && !(user.isEmpty){
        let task7 = Process()
        task7.launchPath = "/usr/bin/dscacheutil"
        let args7 : [String] = ["-q", "user", "-a", "name", "\(user)"]
        task7.arguments = args7
        let pipe7 = Pipe()
        task7.standardOutput = pipe7
        task7.launch()
        let results7 = pipe7.fileHandleForReading.readDataToEndOfFile()
        let out7 = String(data: results7, encoding: String.Encoding.utf8)!

        basicsFileHandle.write("\(out7)".data(using: .utf8)!)
    }
}

basicsFileHandle.write("[+] Admin Users:\r----------------------------\r".data(using: .utf8)!)
let task8 = Process()
task8.launchPath = "/usr/bin/dscl"
let args8 : [String] = [".", "-read", "/Groups/admin", "GroupMembership"]
task8.arguments = args8
let pipe8 = Pipe()
task8.standardOutput = pipe8
task8.launch()
let results8 = pipe8.fileHandleForReading.readDataToEndOfFile()
let out8 = String(data: results8, encoding: String.Encoding.utf8)!
basicsFileHandle.write("\(out8)\r".data(using: .utf8)!)

basicsFileHandle.write("[+] Users logged in:\r----------------------------\r".data(using: .utf8)!)

let task9 = Process()
task9.launchPath = "/usr/bin/w"
let pipe9 = Pipe()
task9.standardOutput = pipe9
task9.launch()
let results9 = pipe9.fileHandleForReading.readDataToEndOfFile()
let out9 = String(data: results9, encoding: String.Encoding.utf8)!
basicsFileHandle.write(out9.data(using: .utf8)!)
basicsFileHandle.write("\r".data(using: .utf8)!)

basicsFileHandle.write("[+] Last logins:\r----------------------------\r".data(using: .utf8)!)
let task10 = Process()
task10.launchPath = "/usr/bin/last"
let pipe10 = Pipe()
task10.standardOutput = pipe10
task10.launch()
let results10 = pipe10.fileHandleForReading.readDataToEndOfFile()
let out10 = String(data: results10, encoding: String.Encoding.utf8)!
basicsFileHandle.write(out10.data(using: .utf8)!)
basicsFileHandle.write("\r".data(using: .utf8)!)


//-----lscollector
if keepLSDataSettings == "true"{
    var lsRegFilename = "lsregister-dump.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(lsRegFilename)", contents: nil, attributes: nil)
    let t = Process()
    t.launchPath = "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"
    let a = ["-dump"]
    t.arguments = a
    let p = Pipe()
    t.standardOutput = p
    t.launch()
    let r = p.fileHandleForReading.readDataToEndOfFile()
    let o = String(data: r, encoding: .utf8)!

    let lsRegFileURL = URL(fileURLWithPath: "\(collectionFolderName)/\(lsRegFilename)")

    let lsRegFileHandle = try FileHandle(forWritingTo: lsRegFileURL)
    
    sleep(2)

    lsRegFileHandle.write(o.data(using: .utf8)!)
    lsRegFileHandle.write("\r".data(using: .utf8)!)
}
    
//bash_config collector
if bashConfigCollectorInfo == "true"{
    var bashCollectorFile = "bash_collector_data.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(bashCollectorFile)", contents: nil, attributes: nil)
    let bashCollectorURL = URL(fileURLWithPath: "\(collectionFolderName)/\(bashCollectorFile)")
    let bashCollectorFileHandle = try FileHandle(forWritingTo: bashCollectorURL)
    
    for user in namesList {
        if user.prefix(1) != "_" && user != "daemon" && user != "nobody" && !(user.isEmpty){
            bashCollectorFileHandle.write("Username: \(user)\r----------------------------\r".data(using: .utf8)!)
            
            if (fileMan.fileExists(atPath: "/Users/\(user)/.bash_profile")){
                let data1 = try String(contentsOfFile: "/Users/\(user)/.bash_profile")
                bashCollectorFileHandle.write("bash_profile data:\r".data(using: .utf8)!)
                bashCollectorFileHandle.write(data1.data(using: .utf8)!)
                bashCollectorFileHandle.write("\r".data(using: .utf8)!)
            }
            
            if (fileMan.fileExists(atPath: "/Users/\(user)/.bash_login")){
                let data2 = try String(contentsOfFile: "/Users/\(user)/.bash_login")
                bashCollectorFileHandle.write("bash_login data:\r".data(using: .utf8)!)
                bashCollectorFileHandle.write(data2.data(using: .utf8)!)
                bashCollectorFileHandle.write("\r".data(using: .utf8)!)
            }
            
            if (fileMan.fileExists(atPath: "/Users/\(user)/.profile")){
                let data3 = try String(contentsOfFile: "/Users/\(user)/.profile")
                bashCollectorFileHandle.write(".profile data:\r".data(using: .utf8)!)
                bashCollectorFileHandle.write(data3.data(using: .utf8)!)
                bashCollectorFileHandle.write("\r".data(using: .utf8)!)
            }
            
            if (fileMan.fileExists(atPath: "/Users/\(user)/.bash_logout")){
                let data4 = try String(contentsOfFile: "/Users/\(user)/.bash_logout")
                bashCollectorFileHandle.write("bash_logout data:\r".data(using: .utf8)!)
                bashCollectorFileHandle.write(data4.data(using: .utf8)!)
                bashCollectorFileHandle.write("\r".data(using: .utf8)!)
            }
            
        }
    }
    
}

//bash history collector
if bashHistCollectorInfo == "true" {
    var bashHistFile = "bash_history_data.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(bashHistFile)", contents: nil, attributes: nil)
    let bashHistURL = URL(fileURLWithPath: "\(collectionFolderName)/\(bashHistFile)")
    let bashHistFileHandle = try FileHandle(forWritingTo: bashHistURL)
    
    for user in namesList{
        if user.prefix(1) != "_" && user != "daemon" && user != "nobody" && !(user.isEmpty){
            bashHistFileHandle.write("Username: \(user)\r----------------------------\r".data(using: .utf8)!)
            
            if (fileMan.fileExists(atPath: "/Users/\(user)/.bash_history")){
                do {
                    let d1 = try String(contentsOfFile: "/Users/\(user)/.bash_history")
                                   bashHistFileHandle.write("bash_history data:\r".data(using: .utf8)!)
                                   bashHistFileHandle.write(d1.data(using: .utf8)!)
                                   bashHistFileHandle.write("\r".data(using: .utf8)!)
                    
                }
                catch {
                    bashHistFileHandle.write("[-] Unable to open .bash_history file for this user".data(using: .utf8)!)
                }
                
               
            }
        }
    }
}

//browser collector
if browserCollectorInfo == "true"{
    var browserCollectorFile = "browser_ext_info.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(browserCollectorFile)", contents: nil, attributes: nil)
    
    let browserCollectorURL = URL(fileURLWithPath: "\(collectionFolderName)/\(browserCollectorFile)")
    
    let browserCollectorFileHandle = try FileHandle(forWritingTo: browserCollectorURL)
    
    for user in namesList{
        if user.prefix(1) != "_" && user != "daemon" && user != "nobody" && !(user.isEmpty){
            browserCollectorFileHandle.write("\r----------------------------\rUsername: \(user)\r----------------------------\r".data(using: .utf8)!)
           
            //safari extensions search here
           
           var isDir = ObjCBool(true)
            if fileMan.fileExists(atPath: "/Users/\(user)/Library/Safari/Extensions", isDirectory: &isDir){
                browserCollectorFileHandle.write("--->Safari Extensions Search:\r".data(using: .utf8)!)
                var dirListing = try fileMan.contentsOfDirectory(atPath: "/Users/\(user)/Library/Safari/Extensions")
                
                for file in dirListing{
                    
                    if file.hasSuffix(".safariextz"){
                        browserCollectorFileHandle.write("/Users/\(user)/Library/Safari/Extensions/\(file)".data(using: .utf8)!)
                    }
                }
            
            }
            else {
                browserCollectorFileHandle.write("--->Safari Extensions Search:\r".data(using: .utf8)!)
                browserCollectorFileHandle.write("[-] No Safari Extensions Found.\r".data(using: .utf8)!)
            }
            
            //chrome extensions search here
            if fileMan.fileExists(atPath: "/Users/\(user)/Library/Application Support/Google/Chrome/Default/Extensions", isDirectory: &isDir){
                let enumerator = fileMan.enumerator(atPath: "/Users/\(user)/Library/Application Support/Google/Chrome/Default/Extensions")
                            browserCollectorFileHandle.write("--->Chrome Extensions Search:\r".data(using: .utf8)!)
                            
                            while let each = enumerator?.nextObject() as? String {
                            
                                if each.contains("manifest.json"){
                                    let manifestPath = "/Users/\(user)/Library/Application Support/Google/Chrome/Default/Extensions/\(each)"
                                    var initLine = "=========> \(manifestPath)\r"
                                    browserCollectorFileHandle.write(initLine.data(using: .utf8)!)
                                    let manifestData = try! String(contentsOfFile: manifestPath)
                    
                                    let lines = manifestData.split(separator: "\n")
                                    for line in lines{
                                        if line.contains(##""name":"##){
                                            var extName = line.replacingOccurrences(of: "\"name\"", with: "name")
                                            browserCollectorFileHandle.write(extName.data(using: .utf8)!)
                                            browserCollectorFileHandle.write("\r".data(using: .utf8)!)
                                        }
                                        if line.contains(##""description":"##){
                                            var extDesc = line.replacingOccurrences(of: "\"description\"", with: "description")
                                            browserCollectorFileHandle.write(extDesc.data(using: .utf8)!)
                                            browserCollectorFileHandle.write("\r".data(using: .utf8)!)
                                        }
                                        if line.contains(##""permissions":"##){
                                            var extPerm = line.replacingOccurrences(of: "\"permissions\"", with: "permissions")
                                            browserCollectorFileHandle.write(extPerm.data(using: .utf8)!)
                                            browserCollectorFileHandle.write("\r".data(using: .utf8)!)
                                        }
                //
                                    }
                                }
                            }
            }
            else {
                browserCollectorFileHandle.write("--->Chrome Extensions Search:\r".data(using: .utf8)!)
                browserCollectorFileHandle.write("[-] No Chrome Extensions Found.\r".data(using: .utf8)!)
                
            }
            

            //firefox extensions search - need to fix this
            if fileMan.fileExists(atPath: "/Users/\(user)/Library/Application Support/Firefox/Profiles", isDirectory: &isDir){
                
                let enumerator2 = fileMan.enumerator(atPath: "/Users/\(user)/Library/Application Support/Firefox/Profiles")
                
                browserCollectorFileHandle.write("\r--->Firefox Extensions Search:\r".data(using: .utf8)!)
                
                while let item = enumerator2?.nextObject() as? String {
                    if item.hasSuffix(".xpi") && item.contains("/extensions/"){
                    
                        var ffoxExtPath = "/Users/\(user)/Library/Application Support/Firefox/Profiles/\(item)"
    
                        var initLine2 = "=========> \(ffoxExtPath)\r"
                        browserCollectorFileHandle.write(initLine2.data(using: .utf8)!)
                        
                        //need to move this outside of the while loop:
                        try fileMan.createDirectory(atPath: "\(collectionFolderName)/FirefoxExtensions", withIntermediateDirectories: true, attributes: nil)
                        
                        let itemParsed = item.split(separator: "/")
                        for i in itemParsed {
                            if i.contains(".xpi"){
                                var ffoxExtFileName = i
                                let copyToPath = URL(fileURLWithPath: "\(collectionFolderName)/FirefoxExtensions/\(ffoxExtFileName)")
                                let getPath = URL(fileURLWithPath: ffoxExtPath)
                                
                                try fileMan.copyItem(at: getPath, to: copyToPath)
                            }
                        }
                        browserCollectorFileHandle.write("[+] Firefox extension copied to FirefoxExtensions subdirectory.\r".data(using: .utf8)!)
                        
                        
                    }

                    
                }
                
                                        
                
            }
            else{
                browserCollectorFileHandle.write("--->Firefox Extensions Search:\r".data(using: .utf8)!)
                browserCollectorFileHandle.write("[-] No Firefox Extensions Found.\r".data(using: .utf8)!)
                
            }
            
        }
    }
}


//browser and quarantine history code here
if browserHistCollectorInfo == "true"{
    var browserHistFile = "browser_and_quarantine_history.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(browserHistFile)", contents: nil, attributes: nil)
    
    let browseHistCollectorURL = URL(fileURLWithPath: "\(collectionFolderName)/\(browserHistFile)")
      
    let browseHistFileHandle = try FileHandle(forWritingTo: browseHistCollectorURL)
    var isDir = ObjCBool(true)
    
    for user in namesList{
        if user.prefix(1) != "_" && user != "daemon" && user != "nobody" && !(user.isEmpty){
            if fileMan.fileExists(atPath: "/Users/\(user)/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2", isDirectory: &isDir){
                browseHistFileHandle.write("Results for user \(user)\r----------------------------\r".data(using: .utf8)!)
                        var db : OpaquePointer?
                        var dbURL = URL(fileURLWithPath: "/Users/\(user)/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
                        if sqlite3_open(dbURL.path, &db) != SQLITE_OK{
                            browseHistFileHandle.write("[-] Could not open quarantive events database.".data(using: .utf8)!)
                        }else {
                            
                            let queryString = "select datetime(LSQuarantineTimeStamp, 'unixepoch') as last_visited, LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString, LSQuarantineOriginURLString from LSQuarantineEvent where LSQuarantineDataURLString is not null order by last_visited;"

                            var queryStatement: OpaquePointer? = nil
                            
                            if sqlite3_prepare_v2(db, queryString, -1, &queryStatement, nil) == SQLITE_OK{
                                while sqlite3_step(queryStatement) == SQLITE_ROW {
                                    let col1 = sqlite3_column_text(queryStatement, 0)
                                    if col1 != nil{
                                        nm1 = String(cString: col1!)
                                        
                                    }

                                    let col2 = sqlite3_column_text(queryStatement, 1)
                                    if col2 != nil{
                                        nm2 = String(cString: col2!)
                                    }
                                    
                                    let col3 = sqlite3_column_text(queryStatement, 2)
                                    if col3 != nil{
                                        nm3 = String(cString:col3!)
                                    }
                                    
                                    
                                    let col4 = sqlite3_column_text(queryStatement, 3)
                                    if col4 != nil{
                                        nm4 = String(cString: col4!)
                                    }
                                    
                                    
                                    browseHistFileHandle.write("Date: \(nm1) | App: \(nm2) | File: \(nm3) | OriginURL: \(nm4)\r".data(using: .utf8)!)

                                }
            //
                                sqlite3_finalize(queryStatement)
                            }
                            
                            
                        }

                    }
                    else {
                        browseHistFileHandle.write("[-] QuarantineEventsV2 database not found for user \(user)\r".data(using: .utf8)!)
                    }
            
            //safari history search
            if fileMan.fileExists(atPath: "/Users/\(user)/Library/Safari/History.db", isDirectory: &isDir){
                browseHistFileHandle.write("\r[+] Safari history results for user \(user):\r----------------------------\r".data(using: .utf8)!)
                var db : OpaquePointer?
                var dbURL = URL(fileURLWithPath: "/Users/\(user)/Library/Safari/History.db")
                if sqlite3_open(dbURL.path, &db) != SQLITE_OK{
                    browseHistFileHandle.write("[-] Could not open the Safari History.db file for user \(user)\r".data(using: .utf8)!)
                }else {
                    //let queryString = "select history_visits.visit_time, history_items.url from history_visits, history_items where history_visits.history_item=history_items.id;"
                    let queryString = "select datetime(history_visits.visit_time + 978307200, 'unixepoch') as last_visited, history_items.url from history_visits, history_items where history_visits.history_item=history_items.id order by last_visited;"
                    var queryStatement: OpaquePointer? = nil
                    
                    if sqlite3_prepare_v2(db, queryString, -1, &queryStatement, nil) == SQLITE_OK{
                        while sqlite3_step(queryStatement) == SQLITE_ROW{
                            let col1 = sqlite3_column_text(queryStatement, 0)
                            if col1 != nil{
                                visitDate = String(cString: col1!)
                                
                            }
                            let col2 = sqlite3_column_text(queryStatement, 1)
                            if col2 != nil{
                                histURL = String(cString: col2!)
                                
                            }
                            
                            browseHistFileHandle.write("Date: \(visitDate) | URL: \(histURL)\r".data(using: .utf8)!)
                            
                        }
                        sqlite3_finalize(queryStatement)
                    }
                }
            }
            else {
                browseHistFileHandle.write("[-] Safari History.db database not found for user \(user)\r".data(using: .utf8)!)
            }
            
            //chrome history search
            if fileMan.fileExists(atPath: "/Users/\(user)/Library/Application Support/Google/Chrome/Default/History", isDirectory: &isDir){
                browseHistFileHandle.write("\r[+] Chrome history results for user \(user):\r----------------------------\r".data(using: .utf8)!)
                var db : OpaquePointer?
                var dbURL = URL(fileURLWithPath: "/Users/\(user)/Library/Application Support/Google/Chrome/Default/History")
                
                if sqlite3_open(dbURL.path, &db) != SQLITE_OK{
                    browseHistFileHandle.write("[-] Could not open the Chrome history database file for user \(user)".data(using: .utf8)!)
                    
                } else{
                    
                    let queryString = "select datetime(last_visit_time/1000000-11644473600, \"unixepoch\") as last_visited, url, title from urls order by last_visited;"
                    
                    var queryStatement: OpaquePointer? = nil
                    
                    if sqlite3_prepare_v2(db, queryString, -1, &queryStatement, nil) == SQLITE_OK{
                        
                        while sqlite3_step(queryStatement) == SQLITE_ROW{
                            
                            
                            let col1 = sqlite3_column_text(queryStatement, 0)
                            if col1 != nil{
                                cVisitDate = String(cString: col1!)
                                
                            }
                            
                            let col2 = sqlite3_column_text(queryStatement, 1)
                            if col2 != nil{
                                cUrl = String(cString: col2!)
                                
                            }
                            
                            let col3 = sqlite3_column_text(queryStatement, 2)
                            if col3 != nil{
                                cTitle = String(cString: col3!)
                                
                            }
                            
                            
                             browseHistFileHandle.write("Date: \(cVisitDate) | URL: \(cUrl) | Title: \(cTitle)\r".data(using: .utf8)!)
                            
                        }
                        
                        sqlite3_finalize(queryStatement)
                       
                        
                    }
                    else {
                        print("\r[-] Issue with preparing the Chrome History database...this may be because something is currently writing to it (i.e., an active Chrome browser)...kill the browser and try again")
                    }
                    
                }
            }
            else{
                browseHistFileHandle.write("[-] Chrome History database not found for user \(user)\r".data(using: .utf8)!)
            }
            
            
            if fileMan.fileExists(atPath: "/Users/\(user)/Library/Application Support/Firefox/Profiles/"){
                let fileEnum = fileMan.enumerator(atPath: "/Users/\(user)/Library/Application Support/Firefox/Profiles/")
                browseHistFileHandle.write("\r[+] Firefox history results for user \(user):\r----------------------------\r".data(using: .utf8)!)
                
                while let each = fileEnum?.nextObject() as? String {
                    if each.contains("places.sqlite"){
                        let placesDBPath = "/Users/\(user)/Library/Application Support/Firefox/Profiles/\(each)"
                        var db : OpaquePointer?
                        var dbURL = URL(fileURLWithPath: placesDBPath)
                        
                        var printTest = sqlite3_open(dbURL.path, &db)
                        
                        if sqlite3_open(dbURL.path, &db) != SQLITE_OK{
                            browseHistFileHandle.write("[-] Could not open the Firefox history database file for user \(user)".data(using: .utf8)!)
                        } else {
                            
                            let queryString = "select datetime(visit_date/1000000,'unixepoch') as time, url FROM moz_places, moz_historyvisits where moz_places.id=moz_historyvisits.place_id order by time;"
                            
                            var queryStatement: OpaquePointer? = nil
                            
                            if sqlite3_prepare_v2(db, queryString, -1, &queryStatement, nil) == SQLITE_OK{
                                
                                while sqlite3_step(queryStatement) == SQLITE_ROW{
                                    let col1 = sqlite3_column_text(queryStatement, 0)
                                    if col1 != nil{
                                        ffoxDate = String(cString: col1!)
                                    }
                                    
                                    let col2 = sqlite3_column_text(queryStatement, 1)
                                    if col2 != nil{
                                        ffoxURL = String(cString: col2!)
                                    }
                                                                        
                                     browseHistFileHandle.write("Date: \(ffoxDate) | URL: \(ffoxURL)\r".data(using: .utf8)!)
                                    
                                }
                                
                                sqlite3_finalize(queryStatement)
                               
                            }
                            
                            
                        }
                    }
                }
            }
            else {
                browseHistFileHandle.write("[-] Firefox places.sqlite database not found for user \(user)\r".data(using: .utf8)!)
            }
            
        }
        
        
    }
    
    
    
}

//certs check
if certsCollectorInfo == "true"{
    
    var certsFile = "cert_data.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(certsFile)", contents: nil, attributes: nil)
    
    let certsFileURL = URL(fileURLWithPath:"\(collectionFolderName)/\(certsFile)")
    
    let certsFileHandle = try FileHandle(forWritingTo: certsFileURL)
    
    for user in namesList {

        do {
            if user.prefix(1) != "_" && user != "daemon" && user != "nobody" && !(user.isEmpty){
                
                let dispatcher = DispatchQueue.global(qos: .background)
                dispatcher.async {
                                    let certTask = Process()
                    
                                    certTask.launchPath = "/usr/bin/sudo"
                                    let certArgs : [String] = ["-u", "\(user)", "security", "dump-trust-settings"]
                    
                                    certTask.arguments = certArgs
                                    let certPipe = Pipe()
                                    certTask.standardOutput = certPipe
                                    certTask.launch()
                    let certResults = certPipe.fileHandleForReading.readDataToEndOfFile()
                    let certOut = String(data: certResults, encoding: String.Encoding.utf8)!
                    if !(certOut.isEmpty){
                        certsFileHandle.write("Certificate Trust Settings for user \(user):\r----------------------------\r\(certOut)\r\r".data(using: .utf8)!)
                    }

                }

            }

        }
        catch {
            certsFileHandle.write("[-] Error while attempting to write certificate data for user \(user).\r".data(using: .utf8)!)
        }

    }
    
    let certTask2 = Process()
                       certTask2.launchPath = "/usr/bin/security"
                       let certArgs2 : [String] = ["dump-trust-settings", "-d"]
                       certTask2.arguments = certArgs2
                       let certPipe2 = Pipe()
                       certTask2.standardOutput = certPipe2
                       certTask2.launch()
                       let certResults2 = certPipe2.fileHandleForReading.readDataToEndOfFile()
                       let certOut2 = String(data: certResults2, encoding: String.Encoding.utf8)!

                        certsFileHandle.write("Admin certifiate info:\r----------------------------\r\(certOut2)\r\r".data(using: .utf8)!)


                       let certTask3 = Process()
                       certTask3.launchPath = "/usr/bin/security"
                       let certArgs3 : [String] = ["dump-trust-settings", "-s"]
                       certTask3.arguments = certArgs3
                       let certPipe3 = Pipe()
                       certTask3.standardOutput = certPipe3
                       certTask3.launch()
                       let certResults3 = certPipe3.fileHandleForReading.readDataToEndOfFile()
                       let certOut3 = String(data: certResults3, encoding: String.Encoding.utf8)!

                        certsFileHandle.write("System certifiate info:\r----------------------------\r\(certOut3)\r\r".data(using: .utf8)!)

    
    
}


if installationCollectorInfo == "true"{
    var installCollectorFilename = "installs.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(installCollectorFilename)", contents: nil, attributes: nil)
    let installFileURL = URL(fileURLWithPath: "\(collectionFolderName)/\(installCollectorFilename)")
    let installFileHandle = try FileHandle(forWritingTo: installFileURL)
    
    var isDir = ObjCBool(true)
    var installList = [String]()
    var installListNoExt = [String]()
    
    
    if fileMan.fileExists(atPath: "/private/var/db/receipts/", isDirectory: &isDir){
        let fEnum = fileMan.enumerator(atPath: "/private/var/db/receipts")
        while let eachFile = fEnum?.nextObject() as? String{
            if eachFile.hasSuffix(".plist"){
                installList.append(eachFile)
            }
            
            for item in installList{
                installFileHandle.write("\r\r[+] /private/var/db/receipts/\(item)".data(using: .utf8)!)
                installFileHandle.write("\r--------------------------------------------------------\r".data(using: .utf8)!)
                
                var pListFormat = PropertyListSerialization.PropertyListFormat.xml
                var pListData : [String: AnyObject] = [:]
                let pListPath : String? = Bundle.main.path(forResource: "data", ofType: "plist")
                let plistURL = URL(fileURLWithPath: "/private/var/db/receipts/\(item)")
            
                let plistXML = try Data(contentsOf: plistURL)
                
                do {
                    pListData = try PropertyListSerialization.propertyList(from: plistXML, options: .mutableContainersAndLeaves, format: &pListFormat) as! [String:AnyObject]
                    for each in pListData{
                         
                        if each.key == "InstallDate"{
                            var writeString = each.key + ":  " + "\(each.value)\r"
                            installFileHandle.write(writeString.data(using: .utf8)!)
                            
                        }
                        if each.key == "InstallPrefixPath"{
                            var writeString = each.key + ":  " + "\(each.value)\r"
                            installFileHandle.write(writeString.data(using: .utf8)!)
                            
                        }
                        if each.key == "InstallProcessName"{
                            var writeString = each.key + ":  " + "\(each.value)\r"
                            installFileHandle.write(writeString.data(using: .utf8)!)
                            
                        }
                        if each.key == "PackageFileName"{
                            var writeString = each.key + ":  " + "\(each.value)\r"
                            installFileHandle.write(writeString.data(using: .utf8)!)
                            
                        }
                        if each.key == "PackageIdentifier"{
                            var writeString = each.key + ":  " + "\(each.value)\r"
                            installFileHandle.write(writeString.data(using: .utf8)!)
                            
                        }
                        if each.key == "PackageVersion"{
                            var writeString = each.key + ":  " + "\(each.value)\r"
                            installFileHandle.write(writeString.data(using: .utf8)!)
                            
                        }
    
                    }
                } catch {
                    installFileHandle.write("[-] Error reading plist /private/var/db/receipts/\(item)".data(using: .utf8)!)
                    
                }
                
                
            }
            
//
        }
    }
    
    if fileMan.fileExists(atPath: "/Library/Receipts/InstallHistory.plist"){
        //var installList2 = [String]()
        var instHistCollectorFilename = "install_history.txt"
        fileMan.createFile(atPath: "\(collectionFolderName)/\(instHistCollectorFilename)", contents: nil, attributes: nil)
        let instHistFileURL = URL(fileURLWithPath: "\(collectionFolderName)/\(instHistCollectorFilename)")
        let instHistFileHandle = try FileHandle(forWritingTo: instHistFileURL)
        
        let plistURL = URL(fileURLWithPath: "/Library/Receipts/InstallHistory.plist")
        
        //var parser : XMLParser
        let path = Bundle.main.path(forResource: "File", ofType: "xml")
        
        let fPath = fileMan.urls(for: .documentDirectory, in: .userDomainMask).last?.appendingPathComponent("/Library/Receipts/InstallHistory.plist")
        
        let pData = try String(contentsOf: plistURL)
        var pData2 = Array(pData.split(separator: "\n"))
        
        if pData2[0].contains("version="){
            pData2.remove(at: 0)
            
        }
        
        if pData2[1].contains("DOCTYPE"){
            pData2.remove(at: 1)
            
        }
        
        if pData2[2].contains("version="){
            pData2.remove(at: 2)
            
        }
        
        
        
        for i in pData2{
            var writeToFile = i.replacingOccurrences(of: "<key>", with: "").replacingOccurrences(of: "</key>", with: "").replacingOccurrences(of: "<date>", with: "").replacingOccurrences(of: "</date>", with: "").replacingOccurrences(of: "<string>", with: "").replacingOccurrences(of: "</string>", with: "").replacingOccurrences(of: "<array>", with: "Array:").replacingOccurrences(of: "</array>", with: "").replacingOccurrences(of: "<dict>", with: "").replacingOccurrences(of: "</dict>", with: "").replacingOccurrences(of: "\t\t", with: "")
            
            instHistFileHandle.write(writeToFile.data(using: .utf8)!)
            instHistFileHandle.write("\r".data(using: .utf8)!)
           
        }
        

    }
}

//log collector
if logCollectorInfo == "true"{
    
    var logArgTimeSplit = logArgTime.split{$0 == " "}.map(String.init)
    
    var split1 = logArgTimeSplit[0]
    var split2 = logArgTimeSplit[1]
    
    
    if fileMan.fileExists(atPath: "/usr/bin/log"){
        let logTask = Process()
        logTask.launchPath = "/usr/bin/log"
        let logArgs : [String] = ["collect", "\(split1)", "\(split2)", "--output", "\(collectionFolderName)"]
        logTask.arguments = logArgs
        let logPipe = Pipe()
        logTask.standardOutput = logPipe
        logTask.launch()
        let logResults = logPipe.fileHandleForReading.readDataToEndOfFile()
        let logData = String(data: logResults, encoding: .utf8)!
       
        
        
    }
    
    let fileEnumerator = fileMan.enumerator(atPath: "/var/log")
    var logURL = URL(fileURLWithPath: "\(collectionFolderName)/System_Logs")
    
        try fileMan.createDirectory(at: logURL, withIntermediateDirectories: true, attributes: nil)
        
           while let file = fileEnumerator?.nextObject() as? String {
            
            do {
                if file.contains("system."){
                    var fileURL = URL(fileURLWithPath: "/var/log/\(file)")
                    var copyToURL = URL(fileURLWithPath: "\(collectionFolderName)/System_logs/\(file)")
                    
                    try fileMan.copyItem(at: fileURL, to: copyToURL)
                }
                
            }
           catch {
                print("[-] Error copying \(file) to \(logURL).")
            }
            
        }
    
    let fileEnumerator2 = fileMan.enumerator(atPath: "/var/log/asl/")
    var logURL2 = URL(fileURLWithPath: "\(collectionFolderName)/System_Logs/ASL")
    
    try fileMan.createDirectory(at: logURL2, withIntermediateDirectories: true, attributes: nil)

    while let file2 = fileEnumerator2?.nextObject() as? String {
        
        
        if file2.hasSuffix(".asl"){
            var fileURL2 = URL(fileURLWithPath: "/var/log/asl/\(file2)")
            var copyToURL2 = URL(fileURLWithPath: "\(collectionFolderName)/System_logs/ASL/\(file2)")
            
            try fileMan.copyItem(at: fileURL2, to: copyToURL2)
        }
        
        
        
        
    //ASL Logs
    let fileEnumerator3 = fileMan.enumerator(atPath: "/var/log/asl/Logs/")
    let logSourceURL = URL(fileURLWithPath: "\(collectionFolderName)/System_logs/Log_Data")

    try fileMan.createDirectory(at: logSourceURL, withIntermediateDirectories: true, attributes: nil)

        while let file3 = fileEnumerator3?.nextObject() as? String{
            //do {
            var fileURL3 = URL(fileURLWithPath: "/var/log/asl/Logs/\(file3)")
            var copyToURL3 = URL(fileURLWithPath: "\(collectionFolderName)/System_logs/Log_Data/\(file3)")
            
            let p = try Data(contentsOf: fileURL3)
            let logFileCreator = fileMan.createFile(atPath: "\(collectionFolderName)/System_logs/Log_Data/\(file3)", contents: p, attributes: nil)
            
        }
    
    
    //Audit Logs
        let fileEnumerator4 = fileMan.enumerator(atPath: "/var/audit/")
        
        let auditLogURL = URL(fileURLWithPath: "\(collectionFolderName)/System_Logs/Audit_Logs")
        
        try fileMan.createDirectory(at: auditLogURL, withIntermediateDirectories: true, attributes: nil)
        
        while let file4 = fileEnumerator4?.nextObject() as? String{
            var fileURL4 = URL(fileURLWithPath: "/var/audit/\(file4)")
            
            let i = try Data(contentsOf: fileURL4)
            
            let auditFileCreator = fileMan.createFile(atPath: "\(collectionFolderName)/System_logs/Audit_Logs/\(file4)", contents: i, attributes: nil)
            
        }
        

    }
     
    print("[+] Audit successfully logs copied to \(collectionFolderName)/System_logs/Audit_Logs")
    
}



//network config collector
if networkCollectorInfo == "true"{
    let netDataFile = "network_config.txt"
    let netDataURL = URL(fileURLWithPath: "\(collectionFolderName)/\(netDataFile)")
    fileMan.createFile(atPath: "\(collectionFolderName)/\(netDataFile)", contents: nil, attributes: nil)
    let netDataHandle = try FileHandle(forWritingTo: netDataURL)
    netDataHandle.write("[+] Network Config Data:\r".data(using: .utf8)!)
    
    let netTask = Process()
    netTask.launchPath = "/sbin/ifconfig"
    let netArgs = ["en0"]
    netTask.arguments = netArgs
    let netPipe = Pipe()
    netTask.standardOutput = netPipe
    netTask.launch()
    let netResults = netPipe.fileHandleForReading.readDataToEndOfFile()
    let netData = String(data: netResults, encoding: .utf8)!
    netDataHandle.write("---> ifconfig data:\r".data(using: .utf8)!)
    netDataHandle.write(netData.data(using: .utf8)!)
    netDataHandle.write("\r\r".data(using: .utf8)!)
    
    let netTask2 = Process()
    netTask2.launchPath = "/sbin/ifconfig"
    let netArgs2 = ["en1"]
    netTask2.arguments = netArgs2
    let netPipe2 = Pipe()
    netTask2.standardOutput = netPipe2
    netTask2.launch()
    let netResults2 = netPipe2.fileHandleForReading.readDataToEndOfFile()
    let netData2 = String(data: netResults2, encoding: .utf8)!
    netDataHandle.write(netData2.data(using: .utf8)!)
    netDataHandle.write("\r\r".data(using: .utf8)!)
    
    netDataHandle.write("---> scutil data:\r".data(using: .utf8)!)
    let netTask3 = Process()
    netTask3.launchPath = "/usr/sbin/scutil"
    let netArgs3 = ["--dns"]
    netTask3.arguments = netArgs3
    let netPipe3 = Pipe()
    netTask3.standardOutput = netPipe3
    netTask3.launch()
    let netResults3 = netPipe3.fileHandleForReading.readDataToEndOfFile()
    let netData3 = String(data: netResults3, encoding: .utf8)!
    netDataHandle.write(netData3.data(using: .utf8)!)
    netDataHandle.write("\r\r".data(using: .utf8)!)
    
    let netTask4 = Process()
    netTask4.launchPath = "/usr/sbin/scutil"
    let netArgs4 = ["--proxy"]
    netTask4.arguments = netArgs4
    let netPipe4 = Pipe()
    netTask4.standardOutput = netPipe4
    netTask4.launch()
    let netResults4 = netPipe4.fileHandleForReading.readDataToEndOfFile()
    let netData4 = String(data: netResults4, encoding: .utf8)!
    netDataHandle.write(netData4.data(using: .utf8)!)
    netDataHandle.write("\r\r".data(using: .utf8)!)
    
    netDataHandle.write("---> pfctl data:\r".data(using: .utf8)!)
    
    let myDispatcher = DispatchQueue.global(qos: .background)
    myDispatcher.async {
        let myTask = Process()
        myTask.launchPath = "/usr/bin/sudo"
        let myArgs : [String] = ["pfctl", "-s", "rules"]
        myTask.arguments = myArgs
        let myPipe = Pipe()
        myTask.standardOutput = myPipe
        myTask.launch()
        let myResults = myPipe.fileHandleForReading.readDataToEndOfFile()
        let myOut = String(data: myResults, encoding: String.Encoding.utf8)!
        
        if !(myOut.isEmpty){
            netDataHandle.write(myOut.data(using: .utf8)!)
        }
    }
    sleep(1)
    
    //get /etc/hosts file
    let hostsData = try Data(contentsOf: URL(fileURLWithPath: "/etc/hosts"))
    let hostsFileCreator = fileMan.createFile(atPath: "\(collectionFolderName)/hosts.txt", contents: nil, attributes: nil)
    let hostsFileHandle = try FileHandle(forWritingTo: URL(fileURLWithPath: "\(collectionFolderName)/hosts.txt"))
    
    let hDAta = try String(contentsOf: URL(fileURLWithPath: "/etc/hosts"))
    
    hostsFileHandle.write(hDAta.data(using: .utf8)!)
        
}


//persistence collector
if persistCollectorInfo == "true"{
    print("[+] Collecting persistence data...")
    
    var persistFile = "persistence_data.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(persistFile)", contents: nil, attributes: nil)
    fileMan.createFile(atPath: "\(collectionFolderName)/lsregister.txt", contents: nil, attributes: nil)
    let persistURL = URL(fileURLWithPath: "\(collectionFolderName)/\(persistFile)")
    let persistFileHandle = try FileHandle(forWritingTo: persistURL)
    
    persistFileHandle.write("Persistence Information:".data(using: .utf8)!)
    persistFileHandle.write("\r-------------------------\r".data(using: .utf8)!)
    persistFileHandle.write("\r[+]-------> Login Items:\r".data(using: .utf8)!)
    
    let oScript = ##"tell application "System Events" to get the path of every login item"##
    let k = OSAScript.init(source: oScript)
    var compileErr : NSDictionary?
    k.compileAndReturnError(&compileErr)
    var scriptError : NSDictionary?
    var i = k.executeAndReturnError(&scriptError)!
    var j = "\(i)"
    var oResults = j.replacingOccurrences(of: "<NSAppleEventDescriptor: [ ", with: "").replacingOccurrences(of: "'utxt'", with: "").replacingOccurrences(of: " ]>", with: "").replacingOccurrences(of: ", ", with: "\r").replacingOccurrences(of: "(\"", with: "").replacingOccurrences(of: "\")", with: "")
    persistFileHandle.write(oResults.data(using: .utf8)!)
    persistFileHandle.write("\r".data(using: .utf8)!)
    
        
    persistFileHandle.write("\r[+]-------> Hidden Login Items:\r".data(using: .utf8)!)
    
    let persistPipe1 = Pipe()
    let persistPipe2 = Pipe()
    let pTask1 = Process()
    pTask1.launchPath = "/usr/bin/egrep"
    let pTask1Args = ["-oi", ##"'(/[^/]+)*/Contents/Library/LoginItems/.+\.app'"##, "\(collectionFolderName)/lsregister.txt"]
    pTask1.arguments = pTask1Args
    pTask1.standardOutput = persistPipe1
    
    let pTask2 = Process()
    pTask2.launchPath = "/usr/bin/grep"
    let pTask2Args = ["-v", ##"'/Volumes/.*\.backupdb/'"##]
    pTask2.arguments = pTask1Args
    pTask2.standardInput = persistPipe1
    pTask2.standardOutput = persistPipe2
    
    pTask1.launch()
    pTask2.launch()
    pTask1.waitUntilExit()
    pTask2.waitUntilExit()
    
    let pResults = persistPipe2.fileHandleForReading.readDataToEndOfFile()
    let pResults2 = String(data: pResults, encoding: .utf8)!
    
    if pResults2.isEmpty{
        persistFileHandle.write("[-] No hidden login items found.\r\r".data(using: .utf8)!)
    }
    else {
        persistFileHandle.write(pResults2.data(using: .utf8)!)
        persistFileHandle.write("\r".data(using: .utf8)!)
    }
    
    persistFileHandle.write("\r[+]-------> Kexts:\r".data(using: .utf8)!)
    
    let kPipe = Pipe()
    let kPipe2 = Pipe()
    let kTask = Process()
    kTask.launchPath = "/usr/sbin/kextstat"
    kTask.standardOutput = kPipe
    
    let kTask2 = Process()
    kTask2.launchPath = "/usr/bin/grep"
    let kTask2Args = ["-v", "com.apple"]
    kTask2.arguments = kTask2Args
    kTask2.standardInput = kPipe
    kTask2.standardOutput = kPipe2
    
    kTask.launch()
    kTask2.launch()
    kTask.waitUntilExit()
    kTask2.waitUntilExit()
    
    let kResults = kPipe2.fileHandleForReading.readDataToEndOfFile()
    let kResults2 = String(data: kResults, encoding: .utf8)!
    
    if kResults2.isEmpty{
        persistFileHandle.write("[-] No kext data found.\r\r".data(using: .utf8)!)
    }
    else {
        persistFileHandle.write(kResults2.data(using: .utf8)!)
        persistFileHandle.write("\r".data(using: .utf8)!)
        
    }
    
    persistFileHandle.write("\r[+]-------> Cron Jobs:\r".data(using: .utf8)!)
    persistFileHandle.write("Root:\r".data(using: .utf8)!)
    var rDispatcher = DispatchQueue.global(qos: .background)
    rDispatcher.async {
        var rTask = Process()
        var rPipe = Pipe()
        rTask.launchPath = "/usr/bin/crontab"
        var rArgs = ["-l"]
        rTask.arguments = rArgs
        rTask.standardOutput = rPipe
        rTask.launch()
    
        var rResults = rPipe.fileHandleForReading.readDataToEndOfFile()
        var rResults2 = String(data: rResults, encoding: .utf8)!

        if !(rResults2.isEmpty){
            persistFileHandle.write(rResults2.data(using: .utf8)!)
            persistFileHandle.write("\r".data(using: .utf8)!)
        }
        else {
            persistFileHandle.write("[-] No crontab -l data found.\r".data(using: .utf8)!)
        }
    }
    sleep(1)
    
    persistFileHandle.write("\rUser crontab info:\r".data(using: .utf8)!)
    
    for usr in namesList{
        if usr.prefix(1) != "_" && usr != "daemon" && usr != "nobody" && !(usr.isEmpty){
            var tDispatcher = DispatchQueue.global(qos: .background)
            tDispatcher.async {
                var cTask = Process()
                var cPipe = Pipe()
                cTask.launchPath = "/usr/bin/crontab"
                var cArgs = ["-u", "\(usr)", "-l"]
                cTask.arguments = cArgs
                cTask.standardOutput = cPipe
                cTask.launch()
                
                var cResults = cPipe.fileHandleForReading.readDataToEndOfFile()
                var cResults2 = String(data: cResults, encoding: .utf8)!
                
                if !(cResults2.isEmpty){
                    persistFileHandle.write(cResults2.data(using: .utf8)!)
                    persistFileHandle.write("\r".data(using: .utf8)!)
                }
                else{
                    persistFileHandle.write("[-] No cron data found for user \(usr).\r".data(using: .utf8)!)
                }
                
                
            }
            sleep(1)
            
            
        }
    }
    
    persistFileHandle.write("\r[+]-------> /System/Library/StartupItems:\r".data(using: .utf8)!)
    
    let sEnumerator1 = fileMan.enumerator(atPath: "/System/Library/StartupItems")
    let sEnumerator2 = fileMan.enumerator(atPath: "/Library/StartupItems")
    
    while let item = sEnumerator1?.nextObject() as? String {
        var sTask = Process()
        var sPipe = Pipe()
        sTask.launchPath = "/bin/ls"
        var sArgs = ["-aleO", "\(item)"]
        sTask.arguments = sArgs
        sTask.standardOutput = sPipe
        sTask.launch()
        
        var sResults = sPipe.fileHandleForReading.readDataToEndOfFile()
        var sResults2 = String(data: sResults, encoding: .utf8)!
        
        print(sResults2)
        
        if !(sResults2.isEmpty){
            persistFileHandle.write(sResults2.data(using: .utf8)!)
            persistFileHandle.write("\r".data(using: .utf8)!)
        }
        else {
            persistFileHandle.write("[-] No startup items found.\r".data(using: .utf8)!)
        }
        
    }
    
    persistFileHandle.write("\r[+]-------> /Library/StartupItems:\r".data(using: .utf8)!)
    
    while let item2 = sEnumerator2?.nextObject() as? String {
        var sTask2 = Process()
        var sPipe2 = Pipe()
        sTask2.launchPath = "/bin/ls"
        var sArgs2 = ["-aleO", "\(item2)"]
        sTask2.arguments = sArgs2
        sTask2.standardOutput = sPipe2
        sTask2.launch()
        
        var sResults3 = sPipe2.fileHandleForReading.readDataToEndOfFile()
        var sResults4 = String(data: sResults3, encoding: .utf8)!
        
        print(sResults3)
        
        if !(sResults4.isEmpty){
            persistFileHandle.write(sResults4.data(using: .utf8)!)
            persistFileHandle.write("\r".data(using: .utf8)!)
        }
        else {
            persistFileHandle.write("[-] No startup items found.\r".data(using: .utf8)!)
        }
    }
    
    persistFileHandle.write("\r[+]-------> Login Hooks:\r".data(using: .utf8)!)
    let hookDispatcher = DispatchQueue.global(qos: .background)
    hookDispatcher.async {
           let hookTask = Process()
           hookTask.launchPath = "/usr/bin/sudo"
           let hookArgs : [String] = ["defaults", "read", "com.apple.loginwindow", "LoginHook"]
           hookTask.arguments = hookArgs
           let hookPipe = Pipe()
           hookTask.standardOutput = hookPipe
           hookTask.launch()
           let hookResults = hookPipe.fileHandleForReading.readDataToEndOfFile()
           let hookOut = String(data: hookResults, encoding: String.Encoding.utf8)!
           
           if !(hookOut.isEmpty){
               persistFileHandle.write(hookOut.data(using: .utf8)!)
           }
           else {
            persistFileHandle.write("[-] No \"root\" loginhook data found\r".data(using: .utf8)!)
        }
        
       }
    sleep(1)
    
    for uname in namesList{
        if uname.prefix(1) != "_" && uname != "daemon" && uname != "nobody" && !(uname.isEmpty){
            
            var hDispatcher = DispatchQueue.global(qos: .background)
            hDispatcher.async {
                let hTask = Process()
                hTask.launchPath = "/usr/bin/sudo"
                let hArgs = ["defaults", "read", "/Users/\(uname)/Library/Preferences/com.apple.loginwindow", "LoginHook"]
                hTask.arguments = hArgs
                let hPipe = Pipe()
                hTask.standardOutput = hPipe
                hTask.launch()
                let hResults = hPipe.fileHandleForReading.readDataToEndOfFile()
                let hOut = String(data: hResults, encoding: .utf8)!
                
                if !(hOut.isEmpty){
                    persistFileHandle.write(hOut.data(using: .utf8)!)
                }
                else {
                    persistFileHandle.write("[-] No loginhook data found for user \(uname)\r".data(using: .utf8)!)
                }
            }
            
            sleep(1)
        }
    }
    
    persistFileHandle.write("\r[+]-------> Launch Information:\r".data(using: .utf8)!)
    persistFileHandle.write("[+] System:\r".data(using: .utf8)!)
    
    let launchEnum = fileMan.enumerator(atPath: "/Library/LaunchAgents")
    let launchDEnum = fileMan.enumerator(atPath: "/Library/LaunchDaemons")
    
    //system launch agents:
    while let launchItem = launchEnum?.nextObject() as? String{
        var lTask = Process()
        var lPipe = Pipe()
        lTask.launchPath = "/bin/ls"
        var lArgs = ["-aleO", "/Library/LaunchAgents/\(launchItem)"]
        lTask.arguments = lArgs
        lTask.standardOutput = lPipe
        lTask.launch()
        
        let lResults = lPipe.fileHandleForReading.readDataToEndOfFile()
        let lOut = String(data: lResults, encoding: .utf8)!
        
        if !(lOut.isEmpty){
            persistFileHandle.write(lOut.data(using: .utf8)!)
        }
        else {
            persistFileHandle.write("[-] No system launch agents found.".data(using: .utf8)!)
        }
    }
    
    //system launch daemons:
    while let launchItem2 = launchDEnum?.nextObject() as? String{
        var lTask2 = Process()
        var lPipe2 = Pipe()
        lTask2.launchPath = "/bin/ls"
        var lArgs2 = ["-aleO", "/Library/LaunchDaemons/\(launchItem2)"]
        lTask2.arguments = lArgs2
        lTask2.standardOutput = lPipe2
        lTask2.launch()
        
        let lResults2 = lPipe2.fileHandleForReading.readDataToEndOfFile()
        let lOut2 = String(data: lResults2, encoding: .utf8)!
        
        if !(lOut2.isEmpty){
            persistFileHandle.write(lOut2.data(using: .utf8)!)
        }
        else {
            persistFileHandle.write("[-] No system launch daemons found.".data(using: .utf8)!)
        }
    }
    
    
    
    for puser in namesList{
        if puser.prefix(1) != "_" && puser != "daemon" && puser != "nobody" && !(puser.isEmpty){
            var launchfoldertoEnum = "/Users/\(puser)/Library/LaunchAgents"
            var launchfoldertoEnum2 = "/Users\(puser)/Library/LaunchDaemons"
            
            //enumerate user launch agents
            persistFileHandle.write("\r[+] Launch Agents for user \(puser):\r".data(using: .utf8)!)
            var launchAgentEnum = fileMan.enumerator(atPath: launchfoldertoEnum)
            while var item = launchAgentEnum?.nextObject() as? String{
                var laTask = Process()
                var laPipe = Pipe()
                laTask.launchPath = "/bin/ls"
                var laArgs = ["-aleO", "/Users/\(puser)/Library/LaunchAgents/\(item)"]
                laTask.arguments = laArgs
                laTask.standardOutput = laPipe
                laTask.launch()
                var laResults = laPipe.fileHandleForReading.readDataToEndOfFile()
                var laOut = String(data: laResults, encoding: .utf8)!
                
                if !(laOut.isEmpty){
                    persistFileHandle.write(laOut.data(using: .utf8)!)
                }
                else {
                    persistFileHandle.write("[-] No launch agents found for user \(puser).\r".data(using: .utf8)!)
                }
                
            }
            

            
        }
    }
    
    
    //launchctl Listing
    if geteuid() == 0 {
        persistFileHandle.write("\r[+] Root agents/daemons:\r".data(using: .utf8)!)
        var rootProc = Process()
        var rootPipe = Pipe()
        rootProc.launchPath = "/bin/launchctl"
        var rootArgs = ["list"]
        rootProc.arguments = rootArgs
        rootProc.standardOutput = rootPipe
        rootProc.launch()
        var rootResults = rootPipe.fileHandleForReading.readDataToEndOfFile()
        var rootOut = String(data: rootResults, encoding: .utf8)!
        
        persistFileHandle.write(rootOut.data(using: .utf8)!)
    }
    else {
        persistFileHandle.write("\r[+] User agents:\r".data(using: .utf8)!)
        var rootProc = Process()
        var rootPipe = Pipe()
        rootProc.launchPath = "/bin/launchctl"
        var rootArgs = ["list"]
        rootProc.arguments = rootArgs
        rootProc.standardOutput = rootPipe
        rootProc.launch()
        var rootResults = rootPipe.fileHandleForReading.readDataToEndOfFile()
        var rootOut = String(data: rootResults, encoding: .utf8)!
        
        persistFileHandle.write(rootOut.data(using: .utf8)!)
    }
    
    //copy over other persistence artifacts
    try fileMan.createDirectory(atPath: "\(collectionFolderName)/Persistence_Artifacts", withIntermediateDirectories: true, attributes: nil)
    
    let jobEnum = fileMan.enumerator(atPath: "/var/at/jobs")
    while let job = jobEnum?.nextObject() as? String{
        var jobFile = URL(fileURLWithPath: "/var/at/jobs/\(job)")
        var copyToDest = URL(fileURLWithPath: "\(collectionFolderName)/Persistence_Artifacts/\(job)")
        var jobData = try Data(contentsOf: jobFile)
        let jobFileCreator = fileMan.createFile(atPath: "\(collectionFolderName)/Persistence_Artifacts/\(job)", contents: jobData, attributes: nil)
        
    }
    
    //copy audit_warn file:
    if fileMan.fileExists(atPath: "/etc/security/audit_warn"){
        var auditURL = URL(fileURLWithPath: "/etc/security/audit_warn")
        var auditData = try Data(contentsOf: auditURL)
        fileMan.createFile(atPath: "\(collectionFolderName)/Persistence_Artifacts/audit_warn", contents: auditData, attributes: nil)
    }
    
    
    //copy rc.common:
    if fileMan.fileExists(atPath: "/etc/rc.common"){
        var rccommonURL = URL(fileURLWithPath: "/etc/rc.common")
        var rccommonData = try Data(contentsOf: rccommonURL)
        fileMan.createFile(atPath: "\(collectionFolderName)/Persistence_Artifacts/rc.common", contents: rccommonData, attributes: nil)
        
    }
    
    //copy launchd.conf:
    
    if fileMan.fileExists(atPath: "/etc/launchd.conf"){
        var launchdURL = URL(fileURLWithPath: "/etc/launchd.conf")
        var launchdData = try Data(contentsOf: launchdURL)
        fileMan.createFile(atPath: "\(collectionFolderName)/Persistence_Artifacts/launchd.conf", contents: launchdData, attributes: nil)
    }
    

    print("[+] Copied additional persistence artifacts that were available to \(collectionFolderName)/Persistence_Artifacts".data(using: .utf8)!)
    
}

//process info collector
if processCollectorInfo == "true"{
    
    //get running process info
    try fileMan.createDirectory(atPath: "\(collectionFolderName)/Process_Data", withIntermediateDirectories: true, attributes: nil)
    
    var psData = "processes.txt"
    try fileMan.createFile(atPath: "\(collectionFolderName)/Process_Data/\(psData)", contents: nil, attributes: nil)
    
    let processFileURL = URL(fileURLWithPath: "\(collectionFolderName)/Process_Data/\(psData)")
    let processFileHandle = try FileHandle(forWritingTo: processFileURL)
    
    var processProc = Process()
    var processPipe = Pipe()
    processProc.launchPath = "/bin/ps"
    var processArgs = ["axo", "user,pid,ppid,start,time,command"]
    processProc.arguments = processArgs
    processProc.standardOutput = processPipe
    processProc.launch()
    var processResults = processPipe.fileHandleForReading.readDataToEndOfFile()
    var processOut = String(data: processResults, encoding: .utf8)!
    processFileHandle.write(processOut.data(using: .utf8)!)
    
    //get process files
    var psData2 = "processes_files.txt"
    try fileMan.createFile(atPath: "\(collectionFolderName)/Process_Data/\(psData2)", contents: nil, attributes: nil)
    
    let procFileURL = URL(fileURLWithPath: "\(collectionFolderName)/Process_Data/\(psData2)")
    let procFileHandle = try FileHandle(forWritingTo: procFileURL)
    
    var procProc = Process()
    var procPipe = Pipe()
    procProc.launchPath = "/usr/sbin/lsof"
    procProc.standardOutput = procPipe
    procProc.launch()
    var procResults = procPipe.fileHandleForReading.readDataToEndOfFile()
    var procOut = String(data: procResults, encoding: .utf8)!
    procFileHandle.write(procOut.data(using: .utf8)!)
    
    //get processes network info
    var psData3 = "processes_network.txt"
    try fileMan.createFile(atPath: "\(collectionFolderName)/Process_Data/\(psData3)", contents: nil, attributes: nil)
    
    let pnFileURL = URL(fileURLWithPath: "\(collectionFolderName)/Process_Data/\(psData3)")
    let pnFileHandle = try FileHandle(forWritingTo: pnFileURL)
    
    var pnProc = Process()
    var pnPipe = Pipe()
    pnProc.launchPath = "/usr/sbin/lsof"
    var pnArgs = ["-i"]
    pnProc.arguments = pnArgs
    pnProc.standardOutput = pnPipe
    pnProc.launch()
    var pnResults = pnPipe.fileHandleForReading.readDataToEndOfFile()
    var pnOut = String(data: pnResults, encoding: .utf8)!
    pnFileHandle.write(pnOut.data(using: .utf8)!)
    
}

//profile collector
if profileCollectorInfo == "true"{
    try fileMan.createDirectory(atPath: "\(collectionFolderName)/Profile_Data", withIntermediateDirectories: true, attributes: nil)
       
    var profData = "profiles.txt"
    try fileMan.createFile(atPath: "\(collectionFolderName)/Profile_Data/\(profData)", contents: nil, attributes: nil)
    
    let profileURL = URL(fileURLWithPath: "\(collectionFolderName)/Profile_Data/\(profData)")
    let profileFileHandle = try FileHandle(forWritingTo: profileURL)
    
    var profileProc = Process()
    var profilePipe = Pipe()
    profileProc.launchPath = "/usr/bin/profiles"
    var profileArgs = ["show", "-all"]
    profileProc.arguments = profileArgs
    profileProc.standardOutput = profilePipe
    profileProc.launch()
    var profileResults = profilePipe.fileHandleForReading.readDataToEndOfFile()
    var profileOut = String(data: profileResults, encoding: .utf8)!
    
    profileFileHandle.write(profileOut.data(using: .utf8)!)
}

//suspicious behaviors collector
if suspiciousCollectorInfo == "true"{
    var suspFileName = "suspicious_behaviors.txt"
    try fileMan.createDirectory(atPath: "\(collectionFolderName)/Suspicious_Behaviors", withIntermediateDirectories: true, attributes: nil)
    
    try fileMan.createFile(atPath: "\(collectionFolderName)/Suspicious_Behaviors/\(suspFileName)", contents: nil, attributes: nil)
    
    let suspURL = URL(fileURLWithPath: "\(collectionFolderName)/Suspicious_Behaviors/\(suspFileName)")
    let suspURLHandle = try FileHandle(forWritingTo: suspURL)
    
    //list of processes running from suspicoius paths
    suspURLHandle.write("Suspicious processes\r-----------------------------\r".data(using: .utf8)!)
    
    var suspProc = Process()
    var suspPipe = Pipe()
    suspProc.launchPath = "/bin/ps"
    var suspArgs = ["axo", "pid,comm"]
    suspProc.arguments = suspArgs
    suspProc.standardOutput = suspPipe
    suspProc.launch()
    var suspResults = suspPipe.fileHandleForReading.readDataToEndOfFile()
    var suspOut = String(data: suspResults, encoding: .utf8)!
    
    var suspArray = Array(suspOut.split(separator: "\n"))
    var suspArray2 = [Any]()
    
    for proc in suspArray{
        if (proc.range(of: ##"/\.[^\.]"##) != nil) || proc.contains("/tmp/") || proc.contains("/var/folders/") || proc.contains("/Users/Shared/") || proc.contains("/Library/Containers/"){
            suspArray2.append(proc)
        }
        
    }
    
    if suspArray2.isEmpty{
        suspURLHandle.write("[-] None found".data(using: .utf8)!)
    }
    else{
        for i in suspArray2{
            var i2 = "\(i)"
            suspURLHandle.write(i2.data(using: .utf8)!)
            suspURLHandle.write("\r\r".data(using: .utf8)!)
        }
    }
    
    
    //list suspicious launch agents and daemons
    let launchAEnum = fileMan.enumerator(atPath: "/Library/LaunchAgents")
    let launchDEnum = fileMan.enumerator(atPath: "/Library/LaunchDaemons")
    
    var suspectLAgent = Set<String>()
    var suspectLDaemon = Set<String>()
    var badFoundList = Set<String>()
    var lAgentPathList = Set<String>()
    var badFoundPathList = Set<String>()

    
    //system launch agent enumeration and check:
    while let launchAgent = launchAEnum?.nextObject() as? String{
        let node = try FileWrapper(url: URL(fileURLWithPath: "/Library/LaunchAgents/\(launchAgent)"), options: .immediate)
        if node.isSymbolicLink == false {
            
            if launchAgent.contains("com.apple") && !(launchAgent.contains("aelwriter")) && !(launchAgent.contains("installer.cleanupinstaller")) && !(launchAgent.contains("installer.osmessagetracing")){
                suspectLAgent.insert("/Library/LaunchAgents/\(launchAgent)")

                    }
                    
                    if launchAgent.prefix(1) == "."{
                        suspectLAgent.insert("/Library/LaunchAgents/\(launchAgent)")
                        
                    }
                    
                    var badFound = false
                    var pListFormat = PropertyListSerialization.PropertyListFormat.xml
                    var pListData : [String: AnyObject] = [:]
                    let plistPath : String? = Bundle.main.path(forResource: "data", ofType: "plist")
                    let plistURL = URL(fileURLWithPath: "/Library/LaunchAgents/\(launchAgent)")
                    let plistXML = try Data(contentsOf: plistURL)
                    do {
                        pListData = try PropertyListSerialization.propertyList(from: plistXML, options: .mutableContainersAndLeaves, format: &pListFormat) as! [String:AnyObject]
                        for data in pListData{
                            
                            if data.key.contains("Program"){
                                var progName = data.value
                                var progName2 = "\(progName)"
                                
                                if (progName2.range(of: ##"/\.[^\.]"##) != nil) || progName2.contains("/tmp/") || progName2.contains("/var/folders/") || progName2.contains("/Users/Shared/") || progName2.contains("/Library/Containers/") || progName2.contains("/var/root/") || progName2.prefix(2) == ##"./"## || progName2.contains("python") || progName2 == "sh" || progName2.contains("/bin/sh") || progName2.contains("java") || progName2.contains(##"/."##){
                                    suspectLAgent.insert("/Library/LaunchAgents/\(launchAgent)")

                                }
                                
                                if progName2.contains("curl") || progName2.contains("exec") || progName2.contains("base64.b64decode"){
                                    badFoundList.insert("/Library/LaunchAgents/\(launchAgent)")

                                }
                                
                            }
                            else if data.key.contains("ProgramArguments"){
                                var progName = data.value
                                var progName2 = "\(progName)"
                                
                                if (progName2.range(of: ##"/\.[^\.]"##) != nil) || progName2.contains("/tmp/") || progName2.contains("/var/folders/") || progName2.contains("/Users/Shared/") || progName2.contains("/Library/Containers/") || progName2.contains("/var/root/") || progName2.prefix(2) == ##"./"## || progName2.contains("python") || progName2 == "sh" || progName2.contains("/bin/sh") || progName2.contains("java") || progName2.contains(##"/."##){
                                    suspectLAgent.insert("/Library/LaunchAgents/\(launchAgent)")

                                }
                                
                                if progName2.contains("curl") || progName2.contains("exec") || progName2.contains("base64.b64decode"){
                                    badFoundList.insert("/Library/LaunchAgents/\(launchAgent)")

                                    
                                }
                                
                            }
                            else {
                                ()
                            }
                            
                        }
                    }
                    catch {
                        ()
                    }
            
        }
    }
            
        
        
        //launch daemon enumeration and check
        while let launchDaemon = launchDEnum?.nextObject() as? String{
            let node2 = try FileWrapper(url: URL(fileURLWithPath: "/Library/LaunchDaemons/\(launchDaemon)"), options: .immediate)
            if node2.isSymbolicLink == false {
                
                if launchDaemon.contains("com.apple") && !(launchDaemon.contains("aelwriter")) && !(launchDaemon.contains("installer.cleanupinstaller")) && !(launchDaemon.contains("installer.osmessagetracing")){
                    suspectLDaemon.insert("/Library/LaunchDaemons/\(launchDaemon)")
                        
                    }
                    
                    if launchDaemon.prefix(1) == "."{
                        suspectLDaemon.insert("/Library/LaunchDaemons/\(launchDaemon)")
                        
                    }
                
                    var badFound2 = false
                    var pListFormat2 = PropertyListSerialization.PropertyListFormat.xml
                    var pListData2 : [String: AnyObject] = [:]
                    let plistPath2 : String? = Bundle.main.path(forResource: "data", ofType: "plist")
                    let plistURL2 = URL(fileURLWithPath: "/Library/LaunchDaemons/\(launchDaemon)")
                    let plistXML2 = try Data(contentsOf: plistURL2)
                    
                    do {
                        pListData2 = try PropertyListSerialization.propertyList(from: plistXML2, options: .mutableContainersAndLeaves, format: &pListFormat2) as! [String:AnyObject]
                        for each in pListData2{
                            if each.key.contains("Program"){
                                var name = each.value
                                var name2 = "\(name)"
                                
                                if (name2.range(of: ##"/\.[^\.]"##) != nil) || name2.contains("/tmp/") || name2.contains("/var/folders/") || name2.contains("/Users/Shared/") || name2.contains("/Library/Containers/") || name2.contains("/var/root/") || name2.prefix(2) == ##"./"## || name2.contains("python") || name2 == "sh" || name2.contains("/bin/sh") || name2.contains("java") || name2.contains(##"/."##){
                                    suspectLDaemon.insert("/Library/LaunchDaemons/\(launchDaemon)")
                                    
                                }
                                
                                if name2.contains("curl") || name2.contains("exec") || name2.contains("base64.b64decode"){
                                    badFoundList.insert("/Library/LaunchDaemons/\(launchDaemon)")
                                    
                                }
                                
                            }
                            else if each.key.contains("ProgramArguments") {
                                var name = each.value
                                var name2 = "\(name)"
                                
                                if (name2.range(of: ##"/\.[^\.]"##) != nil) || name2.contains("/tmp/") || name2.contains("/var/folders/") || name2.contains("/Users/Shared/") || name2.contains("/Library/Containers/") || name2.contains("/var/root/") || name2.prefix(2) == ##"./"## || name2.contains("python") || name2 == "sh" || name2.contains("/bin/sh") || name2.contains("java") || name2.contains(##"/."##){
                                    suspectLDaemon.insert("/Library/LaunchDaemons/\(launchDaemon)")
                                    
                                }
                                
                                if name2.contains("curl") || name2.contains("exec") || name2.contains("base64.b64decode"){
                                    badFoundList.insert("/Library/LaunchDaemons/\(launchDaemon)")
                                    
                                }
                                
                            }
                            else {
                                ()
                            }
                            
                        }
                    }
                    catch {
                        ()
                    }
                
            }
        }
            
            
            //user launch agent enumeration and check
            for eachuser in namesList{
                if eachuser.prefix(1) != "_" && eachuser != "daemon" && eachuser != "nobody" && !(eachuser.isEmpty){
                    var usrLaunchAgentPath = "/Users/\(eachuser)/Library/LaunchAgents"
                    if (fileMan.fileExists(atPath: usrLaunchAgentPath)){
                        
                        let userLAEnum = fileMan.enumerator(atPath: "/Users/\(eachuser)/Library/LaunchAgents")
                        
                        while let userLAgent = userLAEnum?.nextObject() as? String{
                                                    
                            let node3 = try FileWrapper(url: URL(fileURLWithPath: "/Users/\(eachuser)/Library/LaunchAgents/\(userLAgent)"), options: .immediate)
                            if node3.isSymbolicLink == false {
                                
                                if userLAgent.contains("com.apple") && !(userLAgent.contains("aelwriter")) && !(userLAgent.contains("installer.cleanupinstaller")) && !(userLAgent.contains("installer.osmessagetracing")){
                                    suspectLAgent.insert("/Users/\(eachuser)/Library/LaunchAgents/\(userLAgent)")

                                }
                                
                                if userLAgent.prefix(1) == "."{
                                    suspectLAgent.insert("/Users/\(eachuser)/Library/LaunchAgents/\(userLAgent)")
                                    
                                }
                                
                                var pListFormat3 = PropertyListSerialization.PropertyListFormat.xml
                                var pListData3 : [String: AnyObject] = [:]
                                let plistPath3 : String? = Bundle.main.path(forResource: "data", ofType: "plist")
                                let plistURL3 = URL(fileURLWithPath: "/Users/\(eachuser)/Library/LaunchAgents/\(userLAgent)")
                                let plistXML3 = try Data(contentsOf: plistURL3)
                                
                                do {
                                    pListData3 = try PropertyListSerialization.propertyList(from: plistXML3, options: .mutableContainersAndLeaves, format: &pListFormat3) as! [String:AnyObject]
                                    for p in pListData3{
                                        
                                        if p.key.contains("Program"){
                                            var pname = p.value
                                            var pname2 = "\(pname)"
                                            
                                            if (pname2.range(of: ##"/\.[^\.]"##) != nil) || pname2.contains("/tmp/") || pname2.contains("/var/folders/") || pname2.contains("/Users/Shared/") || pname2.contains("/Library/Containers/") || pname2.contains("/var/root/") || pname2.prefix(2) == ##"./"## || pname2.contains("python") || pname2 == "sh" || pname2.contains("/bin/sh") || pname2.contains("java") || pname2.contains(##"/."##){
                                                suspectLAgent.insert("/Users/\(eachuser)/Library/LaunchAgents/\(userLAgent)")
                                                
                                            }
                                            if pname2.contains("curl") || pname2.contains("exec") || pname2.contains("base64.b64.decode"){
                                                badFoundList.insert("/Users/\(eachuser)/Library/LaunchAgents/\(userLAgent)")

                                                
                                            }
                                        }
                                        else if p.key.contains("ProgramArguments"){
                                            var pname = p.value
                                            var pname2 = "\(pname)"
                                                                                   
                                            if (pname2.range(of: ##"/\.[^\.]"##) != nil) || pname2.contains("/tmp/") || pname2.contains("/var/folders/") || pname2.contains("/Users/Shared/") || pname2.contains("/Library/Containers/") || pname2.contains("/var/root/") || pname2.prefix(2) == ##"./"## || pname2.contains("python") || pname2 == "sh" || pname2.contains("/bin/sh") || pname2.contains("java") || pname2.contains(##"/."##){
                                                suspectLAgent.insert("/Users/\(eachuser)/Library/LaunchAgents/\(userLAgent)")
                                            
                                                }
                                            if pname2.contains("curl") || pname2.contains("exec") || pname2.contains("base64.b64.decode"){
                                                badFoundList.insert("/Users/\(eachuser)/Library/LaunchAgents/\(userLAgent)")
                                            
                                            }
                                            
                                        }
                                        else {
                                            ()
                                        }
                                    }
                                    
                                }
                                catch {
                                    ()
                                }
                                
                            }
                            
                        }
                        
                    }
                        
                }
                
            }
        
        if suspectLAgent.count > 0 {
            suspURLHandle.write("\rSuspicious launch agents:\r-------------------------------------\r".data(using: .utf8)!)
            for la in suspectLAgent{
                suspURLHandle.write(la.data(using: .utf8)!)
                suspURLHandle.write("\r".data(using: .utf8)!)
            }
        }
        
        if suspectLDaemon.count > 0{
            suspURLHandle.write("\rSuspicious launch daemons:\r------------------------------------\r".data(using: .utf8)!)
            for ld in suspectLDaemon{
                suspURLHandle.write(ld.data(using: .utf8)!)
                suspURLHandle.write("\r".data(using: .utf8)!)
            }
        }
        
        if badFoundList.count > 0{
            suspURLHandle.write("\rBad indicators found:\r---------------------------------------\r".data(using: .utf8)!)
            for bf in badFoundList{
                suspURLHandle.write(bf.data(using: .utf8)!)
                suspURLHandle.write("\r".data(using: .utf8)!)
            }
        }
        
                    

            
            //check for suspicious lines in sudoers file
            let sudoURL = URL(fileURLWithPath: "/etc/sudoers")
            let sudoInfo = try String(contentsOf: sudoURL)
            
            if (sudoInfo.range(of: ##"^[^#].*NOPASSWD: ALL"##) != nil){
                suspURLHandle.write("\r[-] No password required for sudo\r-------------------------------\r".data(using: .utf8)!)
            }
            
            if (sudoInfo.range(of: ##"Defaults !tty_tickets"##) != nil){
                suspURLHandle.write("\r[-] Sudo allowed for all shells\r-------------------------------\r".data(using: .utf8)!)
            }
            
            //check /etc/hosts for suspicious entries
            let hostsURL = URL(fileURLWithPath: "/etc/hosts")
            let hostsInfo = try String(contentsOf: hostsURL)
            
            if (hostsInfo.range(of: ##"^[\d\.]+\s+.*apple\.com"##) != nil){
                suspURLHandle.write("\rBlocking apple.com, possible infection!\r------------------------------\r".data(using: .utf8)!)
            }
            
            if (hostsInfo.range(of: ##"^[\d\.]+\s+.*virustotal\.com"##) != nil){
                suspURLHandle.write("\rBlocking virustotal.com, possible infection!\r------------------------------\r".data(using: .utf8)!)
            }
            
            if (hostsInfo.range(of: ##"^[\d\.]+\s+.*malwarebytes\.com"##) != nil){
                suspURLHandle.write("\rBlocking malwarebytes.com, possible infection!\r------------------------------\r".data(using: .utf8)!)
            }
            
            if (hostsInfo.range(of: ##"^[\d\.]+\s+.*adobe\.com"##) != nil){
                suspURLHandle.write("\rBlocking adobe.com, possible infection!\r------------------------------\r".data(using: .utf8)!)
            }
            

            
        }
        
    //}
    
//}






//new adddition - code to check for running apps
if shouldListApps == "true"{
    let myWorkSpace = NSWorkspace.shared
    let appCount = myWorkSpace.runningApplications.count
    var appListFile = "runningapps.txt"
    fileMan.createFile(atPath: "\(collectionFolderName)/\(appListFile)", contents: nil, attributes: nil)
    
    let appListFileURL = URL(fileURLWithPath: "\(collectionFolderName)/\(appListFile)")

    let appListFileHandle = try FileHandle(forWritingTo: appListFileURL)
    
    appListFileHandle.write("Count of Running Apps: \(appCount)\r".data(using: .utf8)!)
    appListFileHandle.write("********************************************************\r".data(using: .utf8)!)

    var count = 0
    for each in NSWorkspace.shared.runningApplications {
        count = count + 1
        let appName = each.localizedName!
        let appURL = each.bundleURL//!
        let launchDate = each.launchDate
        let pid = each.processIdentifier
        
        if each.isHidden == true {
            hiddenString = "Hidden: YES\r"
        }
        else {
            hiddenString = "Hidden: NO\r"
        }
        appListFileHandle.write("\(count). Name: \(appName)\r".data(using: .utf8)!)
        
        if appURL != nil {
            appListFileHandle.write("===>Path: \(appURL)\r".data(using: .utf8)!)
        }
        
        if launchDate != nil {
            var lString = "\(launchDate)"
            var lString2 = lString.replacingOccurrences(of: "Optional", with: "").replacingOccurrences(of: "(", with: "").replacingOccurrences(of: ")", with: "")
            appListFileHandle.write("===>Launch Date: \(lString2)\r".data(using: .utf8)!)
                
        }
        
        
        if pid != nil {
            var pString = "\(pid)"
            var pString2 = pString.replacingOccurrences(of: "Optional", with: "").replacingOccurrences(of: "(", with: "").replacingOccurrences(of: ")", with: "")
            appListFileHandle.write("===>PID: \(pString2)\r".data(using: .utf8)!)
            
        }

        appListFileHandle.write("\(hiddenString)\r".data(using: .utf8)!)
        
    }
    
}


//file collector
if fileCollectorInfo == "true"{
//    let fileCollPath = "/Library"
//    let ignoreRestricted = "true"
//
//    let nodump = 1
//    let uchg = 2
//    let uappnd = 4
//    let opaque = 8
//    let compressed = 32
//    let hidden = 32768
//    let arch = 65536
//    let schg = 131072
//    let sappnd = 262144
//    let restricted = 524288
//    let sunlnk = 1048576
    
    print("\r[+] Collecting file info data. This may take some time depending on what directory(ies) you are collecting...\r")
    
    let fileCollectorname = "fileinfo.txt"
    let fileCollectorURL = URL(fileURLWithPath: "\(collectionFolderName)/\(fileCollectorname)")
    fileMan.createFile(atPath: "\(collectionFolderName)/\(fileCollectorname)", contents: nil, attributes: nil)
    let fileCollectorHandle = try FileHandle(forWritingTo: fileCollectorURL)
    
    fileCollectorHandle.write("Flags, UID, GID, Mode, Created, Modified, Accessed, Path\r".data(using: .utf8)!)
    
    for usrName in namesList{
        if usrName.prefix(1) != "_" && usrName != "daemon" && usrName != "nobody" && !(usrName.isEmpty){
            var usrFolderEnumerator = fileMan.enumerator(atPath: "/Users/\(usrName)")
            while let folderItem = usrFolderEnumerator?.nextObject() as? String{
                    do {
                        var stats = stat()
                        stat("/Users/\(usrName)/\(folderItem)", &stats)
                        var fflags = "\(stats.st_flags)"
                        var fuid = "\(stats.st_uid)"
                        var fgid = "\(stats.st_gid)"
                        var fmode = "\(stats.st_mode)"
                        var fcreate = "\(stats.st_ctimespec.tv_sec)"
                        var fcreateConvert = NSDate(timeIntervalSince1970: TimeInterval(stats.st_ctimespec.tv_sec))
                        var fmodified = "\(stats.st_mtimespec.tv_sec)"
                        var fmodifiedConvert = NSDate(timeIntervalSince1970: TimeInterval(stats.st_mtimespec.tv_sec))
                        var faccessed = "\(stats.st_atimespec.tv_sec)"
                        var faccessedConvert = NSDate(timeIntervalSince1970: TimeInterval(stats.st_atimespec.tv_sec))
                        var fpath = "/Users/\(usrName)/\(folderItem)"
                    
                        fileCollectorHandle.write("\(fflags), \(fuid), \(fgid), \(fmode), \(fcreateConvert), \(fmodifiedConvert), \(faccessedConvert), \(fpath)\r".data(using: .utf8)!)
                            
                    }
                    catch {
                        fileCollectorHandle.write("[+] Filename: /\(folderItem)\r".data(using: .utf8)!)
                        fileCollectorHandle.write("Unable to get flag data for this file.".data(using: .utf8)!)
                    }
                    
        }
            
            
    }
    
        
    }
    let fileEnumerator1 = fileMan.enumerator(atPath: "/tmp/")
    while let tmpItem = fileEnumerator1?.nextObject() as? String{
        do {
            var stats2 = stat()
            stat("/tmp/\(tmpItem)", &stats2)
            var fflags2 = "\(stats2.st_flags)"
            var fuid2 = "\(stats2.st_uid)"
            var fgid2 = "\(stats2.st_gid)"
            var fmode2 = "\(stats2.st_mode)"
            var fcreate2 = "\(stats2.st_ctimespec.tv_sec)"
            var fcreate2Convert = NSDate(timeIntervalSince1970: TimeInterval(stats2.st_ctimespec.tv_sec))
            var fmodified2 = "\(stats2.st_mtimespec.tv_sec)"
            var fmodified2Convert = NSDate(timeIntervalSince1970: TimeInterval(stats2.st_mtimespec.tv_sec))
            var faccessed2 = "\(stats2.st_atimespec)"
            var faccessed2Convert = NSDate(timeIntervalSince1970: TimeInterval(stats2.st_atimespec.tv_sec))
            var fpath2 = "/tmp/\(tmpItem)"
                                
            fileCollectorHandle.write("\(fflags2), \(fuid2), \(fgid2), \(fmode2), \(fcreate2Convert), \(fmodified2Convert), \(faccessed2Convert), \(fpath2)\r".data(using: .utf8)!)
        }
        catch {
            fileCollectorHandle.write("[+] Filename: /\(tmpItem)\r".data(using: .utf8)!)
            fileCollectorHandle.write("Unable to get flag data for this file.".data(using: .utf8)!)
        }
    }

}

//zipIt code
if zipItSettings == "true"{
    var zipPath = "\(collectionFolderName)/pict.zip"
    let task12 = Process()
    task12.launchPath = "/usr/bin/ditto"
    let args12 : [String] = ["-c", "-k", "--sequesterRsrc", "\(collectionFolderName)", "\(collectionFolderName)/pict.zip"]
    task12.arguments = args12
    let pipe12 = Pipe()
    task12.standardOutput = pipe12
    task12.launch()
    let results12 = pipe12.fileHandleForReading.readDataToEndOfFile()
    let out12 = String(data: results12, encoding: String.Encoding.utf8)!
    var endTime : CFAbsoluteTime = CFAbsoluteTimeGetCurrent()
    let elapsedTime = endTime - startTime
    let elapsed = (elapsedTime*100).rounded()/100
    print("")
    print("[+] Collection complete (elapsed time: \(elapsed)s)")
    
}


          



