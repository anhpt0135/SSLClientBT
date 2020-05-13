# Java Native Setup
1. Install the C/C++ complier on Java IDE:
  Help->Eclipse Marketplace->Find: type in CDT to find and download Eclipse C/C++
2. Download JNI source  
  http://bitbucket.hubblevn.com/projects/JAV/repos/fw_automation/browse/TestAndDebug/SSLClientBT
3. Import the downloaded project
  - File->Import->General->Existing Projects into Workspace->Finish
4. Open C/C++ perspective
  - Window->Perspective->Open Perspective->others->C/C++
  - For jni/makefile, need to modify the -I/usr/lib/jvm/java-11-openjdk-amd64/include -I/usr/lib/jvm/java-11-openjdk-amd64/include/linux flag
  that compatible with current installed java or we can install java-11-openjdk-amd64 for current PC.
5. Build the C/C++ project
6. Run Java program:
  - Window->Perspective->Open Perspective->others->Java(default)
  - Run Configurations->Arguments->VM arguments: -Djava.library.path=jni
# Build a new library for automation test tool
1. Dim *public static void main(String[] args)* 
2. File->Export->Java->JAR file
3. Add the created Jar library into Java automation source.
4. Copy the library file .so into fw_automation/HubbleFWTool/lib
5. Adding -Djava.library.path=lib
6. Run CLIMain.java or frmMain.java

References: 
-[Eclipse for JNI development and debugging on Linux (Java and C) - Red Hat Developer](https://developers.redhat.com/blog/2016/11/03/eclipse-for-jni-development-and-debugging-on-linux-java-and-c/)
-[Java Native Interface (JNI) - Java Programming Tutorial](https://www3.ntu.edu.sg/home/ehchua/programming/java/JavaNativeInterface.html)
