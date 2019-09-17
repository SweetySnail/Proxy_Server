//////////////////////////////////////////////////////////////////////////////////////////
// File Name  : server.c                                                                //
// Date       : 2018/06/08                                                              //
// Os         : Ubuntu 16.04.4 LTS                                                      //
// Author     : Noh Jae Hyun                                                            //
// Student ID : 2014722074                                                              //
// ------------------------------------------------------------------------------------ //
// Title: In this Assembly 3-2, several thread-thread functions are added within	//
// 	  semaphores for logfile added in the previous Assembly 3-1. Like Assembly 3-1, //
// 	  this is implemented so that it only affects logfile            		//
//////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////// Declare header file ///////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/sha.h>  // to use SHA1
#include <sys/stat.h>
#include <dirent.h>  // to use DIR*
#include <pwd.h>  // to use getHomeDir()
#include <time.h>  // to use time
#include <sys/wait.h>  // to use waitpid()
#include <stdlib.h>  // to use exit()
#include <arpa/inet.h>  // to use inet_ntoa()
#include <netdb.h>  // to get host name
#include <signal.h>  // to use signal()
#include <fcntl.h>
#include <pthread.h>  // to use thread()
///////////////////////////// End of declare header file /////////////////////////////////

#define BUFFSIZE 1024
#define PORTNO 38015

//////////////////////////////// Declare global value ////////////////////////////////////
time_t time_main_start, time_main_end;  // to save time
static int count_process = 0;  // to count process
char path_log[50];  // to save log path
FILE *fp;  // to file open, close
int fd, socket_fd;  // to save socket number
int semid;  // to save semaphore ID
//////////////////////////// End of declare global value /////////////////////////////////

///////////////////////////// Declare function prototype /////////////////////////////////
char *sha1_hash(char *input_url, char *hashed_url);  // to make hashed URL
char *getHomeDir(char *home);  // to go Home directory
char *getIPAddr(char *addr);  //  to get Host IP Address
void my_sigalrm();  // to set sigalrm
void my_sigint(int signo);  // to set sigint
static void handler();  // to set handler
void P(int semid);  // to lock semaphore
void V(int semid);  // to unlock semaphore
void* thr_fn(void* message);
///////////////////////// End of declare function prototype //////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////
// Manage Everything                                                                    //
// ==================================================================================== //
// Input  : X                                                                           //
// Output : X                                                                           //
// Purpose: Managing Everything to make Server                                          //
//////////////////////////////////////////////////////////////////////////////////////////
int main()
{
	char input_URL[BUFFSIZE] = {'\0'}, hashed_URL[50] = {'\0'};  // save URL
	char txtName[50];  // save text
	char front_3bit[4] = {'\0'};  // save front_3bit
	char path_home[50], path_cache[50], path_file[100];  // save path
	struct dirent *pFile;  // open, read, close directory
	DIR *pDir;
	time_t now;  // save current time, main start & end time
	struct tm* ltp;
	pid_t PID;  // to fork
	int status;  // save status
	char reply[5];  // save reply(HIT, MISS)
	struct sockaddr_in user_addr, client_addr, server_addr;
	int client_fd, server_fd;
	int len, opt = 1;
	int length = 0;
	char message[255];
	void* tret;
	pthread_t tid;
	int err;

	union semun
	{
		int val;
		struct semid_ds *buf;
		unsigned short int* array;
	} arg;	
						
	signal(SIGALRM, my_sigalrm);  // set SIGALRM
	signal(SIGINT, my_sigint);  // set SIGINT
	signal(SIGCHLD, (void *)handler);  // set SIGCHLD

	time(&time_main_start);  // save start time
	umask(0000);  // set umask for directory permission

	///// make semaphore /////
	if((semid = semget((key_t)38015, 1, IPC_CREAT | 0666)) == -1)
	{
		perror("ERROR: Semget failed \n");  // print error
		exit(1);
	}

	arg.val = 1;

	///// control semaphore /////
	if((semctl(semid, 0, SETVAL, arg)) == -1)
	{
		perror("ERROR: Semget failed \n");  // print error
		exit(1);
	}

	///// save path /////
	chdir(getHomeDir(path_home));
	strcpy(path_cache,getHomeDir(path_home));  // path_home: ~/Home/cache/
	strcat(path_cache,"/cache/");
	strcpy(path_log, getHomeDir(path_home));  // path_log: ~/Home/logfile/
	strcat(path_log,"/logfile/");

	///// make cache dir /////
	pDir = opendir(path_home);  // open directory
	for(pFile=readdir(pDir);pFile;pFile = readdir(pDir))  // check duplicate "cache" directory
	{
		if(strcmp(pFile->d_name,"cache") == 0)
			break;
	}

	if(pFile == NULL)  // if there's no cache, make it
		mkdir("cache", S_IRWXU | S_IRWXG | S_IRWXO);

	///// make logfile dir /////
	rewinddir(pDir);  // rewind directory for check logfile directory
	for(pFile=readdir(pDir);pFile;pFile = readdir(pDir))  // check duplicate "logfile" directory
	{
		if(strcmp(pFile->d_name,"logfile") == 0)
			break;
	}

	if(pFile == NULL)  // if there's no logfile, make it
		mkdir("logfile", S_IRWXU | S_IRWXG | S_IRWXO);

	chdir(path_log);
	fp = fopen("logfile.txt", "a");  // make "logfile.txt" in "logfile" directory
	fclose(fp);
	closedir(pDir);  // close directory

	///// make socket /////
	if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Server: Can't open stream socket \n");
		return 0;
	}

	///// remove bind error /////
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	///// init socket /////
	bzero((char*)&user_addr, sizeof(user_addr));
	user_addr.sin_family = AF_INET;  // set sin_family
	user_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // set sin_addr
	user_addr.sin_port = htons(PORTNO);  // set sin_port

	///// bind socket /////
	if(bind(socket_fd, (struct sockaddr *)&user_addr, sizeof(user_addr)) < 0)
	{
		printf("Server: Can't bind local address \n");
		return 0;
	}

	///// listen /////
	listen(socket_fd, 5);  // wait for http request

	while(1)
	{
		struct in_addr inet_client_address;

		char HTTP_request[BUFFSIZE];  // save request message
		char tmp[BUFFSIZE] = {0, };  // save request line
		char method[20] = {0, };  // save request method
		char *tok = NULL;

		///// accept /////
		len = sizeof(client_addr);
		client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len);  // accept http request

		if(client_fd < 0)
		{
			printf("Server: accept failed. \n");
			return 0;
		}
		inet_client_address.s_addr = client_addr.sin_addr.s_addr;

		///// fork /////
		PID = fork();
		///// sub process /////
		if(PID == 0)
		{
			char HTTP_URL[BUFFSIZE];  // to save URL

			read(client_fd, HTTP_request, BUFFSIZE);  // read & copy request
			strcpy(tmp, HTTP_request);

			tok = strtok(tmp, " ");  // obtain request method
			strcpy(method, tok);

			if(strcmp(method, "GET")  == 0)  // if request method is "GET"
			{
				tok = strtok(NULL, " ");  // obtain request URL
				strcpy(HTTP_URL, tok);
			}
			///// exception handling /////
			else
				exit(0);

			strcpy(input_URL, HTTP_URL);

			///// check duplicate /////
			bzero(reply, sizeof(reply));  // init reply

			sha1_hash(input_URL, hashed_URL);  // hash & save URL
			strncpy(front_3bit,hashed_URL,3);

			///// make "front_3bit" directory /////
			pDir = opendir(path_cache);  // open directory
			for(pFile=readdir(pDir);pFile;pFile = readdir(pDir))  // check duplicate "front_3bit" directory
			{
				if(strcmp(pFile->d_name,front_3bit) == 0)
				break;
			}
			closedir(pDir);  // close directory

			if(pFile == NULL)  // if there's no "front_3bit" directory, make it
			{
				chdir(path_cache);
				mkdir(front_3bit, S_IRWXU | S_IRWXG | S_IRWXO);
			}

			///// make "hashed.txt" /////
			hashed_URL[2] = ' ';  // cut off front_3bit in hashed URL
			strcpy(txtName, strtok(hashed_URL," "));
			strcpy(txtName, strtok(NULL,"\0"));
			strcpy(path_file, path_cache);  // path_file: ~/Home/cache/front_3bit
			strcat(path_file, front_3bit);
			chdir(front_3bit);

			pDir = opendir(path_file);  // open directory
			for(pFile=readdir(pDir);pFile;pFile = readdir(pDir))  // check duplicate "hashed.txt"
			{
				if(strcmp(pFile->d_name,txtName) == 0)
					break;
			}
			closedir(pDir);  // close directory

			char HTTP_response[BUFFSIZE] = {'\0', };

			///// if MISS /////
			if(pFile == NULL)
			{
				char* URL_IP;  // to save IP
				char* Host;  // to save Host Name

				Host = strtok(HTTP_URL, "/");  // Extract HostName 
				Host = strtok(NULL, "/");

				URL_IP = getIPAddr(Host);  // Change HostName to IP Address

				///// init socket /////
				bzero((char*)&server_addr, sizeof(server_addr));
				server_addr.sin_family = AF_INET;  // set sin_family
				server_addr.sin_addr.s_addr = inet_addr(URL_IP);  // set sin_addr
				server_addr.sin_port = htons(80);  // set sin_port

				// make server_fd
				server_fd = socket(PF_INET, SOCK_STREAM, 0);

				// connect server_fd <-> socket_fd
				connect(server_fd, (struct sockaddr*) &server_addr, sizeof(server_addr));

				// send HTTP request to web server
				write(server_fd, HTTP_request, strlen(HTTP_request));

				chdir(path_file);
				fd=open(txtName, O_RDWR | O_CREAT | O_APPEND, 0777);  // make "txtName" file

				alarm(10);  // make alarm(10 sec)
				while((length = read(server_fd, HTTP_response, BUFFSIZE)) > 0)
				{
					alarm(10);
					write(fd,HTTP_response, length);  // write respnose in txtName file
					write(client_fd, HTTP_response, length);  // write response in client socket
					bzero(HTTP_response,sizeof(BUFFSIZE));  // init HTTP_response;
				}
				alarm(0);  // init alarm
				close(fd);  // close "txtName"

				printf("  * PID# %d is waiting for the semaphore. \n", getpid());
				// semaphore start
				P(semid);
				printf("  * PID# %d is in the critical zone. \n", getpid());

				err = pthread_create(&tid, NULL, thr_fn, (void*)message);  // make thread

				if(err!=0)  // if thread create has error
				{
					printf("pthread_create() error. \n");
					return 0;
				}

				chdir(path_log);
				fp = fopen("logfile.txt", "a");
				time(&now);  // save current time
				ltp = localtime(&now);

				fprintf(fp,"[MISS] %s - [%02d/%02d/%02d, %02d:%02d:%02d] \n \n",
				input_URL, ltp->tm_year+1900, ltp->tm_mon+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);

				strcpy(reply,"MISS");  // save result in reply value
				fclose(fp);

				pthread_join(tid, &tret);  // interruption thread until thread is terminated 
				printf("  * TID# %lu is exited \n",tid);

				sleep(rand()%5);
				// semaphore end
				V(semid);
				printf("  * PID# %d exited the critical zone. \n", getpid());
			}
				
			///// if HIT /////
			else
			{
				chdir(path_file);
				// read in txtName file

				fd=open(txtName, O_RDONLY, 0777);  // open txtName file
				bzero(HTTP_response,sizeof(BUFFSIZE));  // init HTTP_response
				while((length = read(fd, HTTP_response, BUFFSIZE)) > 0)
				{
					write(client_fd, HTTP_response, length);  // write response in client socket
					bzero(HTTP_response,sizeof(HTTP_response));  // init HTTP_response
				}
				close(fd);  // close txtName file

				printf("  * PID# %d is waiting for the semaphore. \n", getpid());
				// semaphore start
				P(semid);
				printf("  * PID# %d is in the critical zone. \n", getpid());

				err = pthread_create(&tid, NULL, thr_fn, (void*)message);  // make thread
				if(err!=0)  // if thread create has error
				{
					printf("pthread_create() error. \n");
					return 0;
				}

				///// write log in "logfile.txt" /////
				chdir(path_log);
				fp = fopen("logfile.txt", "a");
				time(&now);  // save current time
				ltp = localtime(&now);

				fprintf(fp,"[HIT] %s/%s - [%02d/%02d/%02d, %02d:%02d:%02d]\n",
				front_3bit, txtName, ltp->tm_year+1900, ltp->tm_mon+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);

				fprintf(fp,"[HIT] %s\n \n", input_URL);

				strcpy(reply,"HIT");  // save result in reply value
				fclose(fp);  // close logfile

				pthread_join(tid, &tret);    // interruption thread until thread is terminated
				printf("  * TID# %lu is exited \n",tid);

				sleep(rand()%5);
				// semaphore end
				V(semid);
				printf("  * PID# %d exited the critical zone. \n", getpid());
			}
			close(client_fd);  // close browser

			exit(0);  // sub process end
		}  // pid == 0 end

	///// process error /////
		if(PID < 0)
			printf("ERROR: Can't Find Process. \n");
	}
	close(socket_fd);  // main process end
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
// change URL(Input URL -> Hashed URL)                                                  //
// ==================================================================================== //
// Input  : char* -> Insert URL                                                         //
//          char* -> Space to save the changed URL                                      //
// Output : char* -> Space where Hashing URL are saved                                  //
// Purpose: To Maintain Security and Make URL Length the Same                           //
//////////////////////////////////////////////////////////////////////////////////////////
char *sha1_hash(char *input_url, char *hashed_url)
{
	unsigned char hashed_160bits[20];
	char hashed_hex[41];
	int i;

	SHA1(input_url,strlen(input_url),hashed_160bits);  // change input URL to 160bits URL

	for(i=0;i<sizeof(hashed_160bits);i++)  // change 160bits URL to hex-decimal URL
		sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);

	strcpy(hashed_url,hashed_hex);  // copy hex-decimal URL to hashed_URL

	return hashed_url;
}

//////////////////////////////////////////////////////////////////////////////////////////
// Space to save home directory                                                         //
// ==================================================================================== //
// Input  : char* -> Space to save home directory                                       //
// Output : char* -> Space where home directories are saved                             //
// Purpose: To save the Home Directory Path                                             //
//////////////////////////////////////////////////////////////////////////////////////////
char *getHomeDir(char *home)
{
	struct passwd *usr_info = getpwuid(getuid());  // Find home path
	strcpy(home, usr_info->pw_dir);  // copy home directory path

	return home;
}

//////////////////////////////////////////////////////////////////////////////////////////
// Extract Host IP Address                                                              //
// ==================================================================================== //
// Input  : char* -> Host Name                                   		 	//
// Output : char* -> Host IP Address				                        //
// Purpose: Used to extract IP addresses from the "HTTP_URL" included in the entered	//
//          request message.                                           			//
//////////////////////////////////////////////////////////////////////////////////////////
char *getIPAddr(char *addr)
{
	struct hostent* hent;
	char * haddr;
	int len = strlen(addr);

	if ( (hent = (struct hostent*)gethostbyname(addr)) != NULL)  // if HostName isn't NULL
		haddr=inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));  // change Host Name to IP Addresss

	return haddr;
}

//////////////////////////////////////////////////////////////////////////////////////////
//  Print alarm message                                                                 //
// ==================================================================================== //
// Input  : X                                      				        //
// Output : X						                                //
// Purpose: If there is no response from HTTP_response, an alarm message is output.	//
//////////////////////////////////////////////////////////////////////////////////////////
void my_sigalrm()
{
	printf("ERROR: Client No Response \n");
	exit(0);
}

//////////////////////////////////////////////////////////////////////////////////////////
//  Print alarm message                                                                 //
// ==================================================================================== //
// Input  : X                                      				        //
// Output : X						                                //
// Purpose: Outputs a message if the proxy is terminated forcibly.			//
//////////////////////////////////////////////////////////////////////////////////////////
void my_sigint(int signo)
{
	printf("  * PID# %d is waiting for the semaphore. \n", getpid());
	// semaphore start
	P(semid);
	printf("  * PID# %d is in the critical zone. \n", getpid());

	chdir(path_log);  // go to path_log
	time(&time_main_end);  // save end time
	fp = fopen("logfile.txt", "a");  // open logfile.txt
	fprintf(fp, "**Server** [Terminated] Run Time: %ld sec. #Sub Process: %d \n\n", time_main_end - time_main_start, count_process);
	fclose(fp);  // close logfile.txt

	close(socket_fd);  // main process end

	// semaphore end
	V(semid);
	printf("  * PID# %d exited the critical zone. \n", getpid());
	exit(0);
}

//////////////////////////////////////////////////////////////////////////////////////////
//  Set Handler 	                                                                //
// ==================================================================================== //
// Input  : X                                      				        //
// Output : X						                                //
// Purpose: Increase the number of processes at the end of each process.		//
//////////////////////////////////////////////////////////////////////////////////////////
static void handler()
{
	pid_t pid;
	int status;
	
	count_process++;  // plus count_process
	while((pid = waitpid(-1, &status, WNOHANG)) > 0);  // wait for child process
}

//////////////////////////////////////////////////////////////////////////////////////////
// P operation	 	                                                                //
// ==================================================================================== //
// Input  : int -> ID to lock                          				        //
// Output : X						                                //
// Purpose: Lock Sempahore.								//
//////////////////////////////////////////////////////////////////////////////////////////
void P(int semid)
{
	struct sembuf pbuf;
	pbuf.sem_num = 0;  // set sem_num
	pbuf.sem_op = -1;  // set sem_op
	pbuf.sem_flg = SEM_UNDO;  // set sem_flg

	if((semop(semid, &pbuf,1)) == -1)  // if semop has error
	{
		perror("P: semop failed");
		exit(1);
	}
}

//////////////////////////////////////////////////////////////////////////////////////////
// V operation 	                                                                	//
// ==================================================================================== //
// Input  : int -> ID to unlock                      				        //
// Output : X						                                //
// Purpose: Unlock Sempahore.								//
//////////////////////////////////////////////////////////////////////////////////////////
void V(int semid)
{
	struct sembuf pbuf;
	pbuf.sem_num = 0;  // set sem_num
	pbuf.sem_op = 1;  // set sem_op
	pbuf.sem_flg = SEM_UNDO;  // set sem_flg

	if((semop(semid, &pbuf,1)) == -1)  // if semop has error
	{
		perror("V: semop failed");
		exit(1);
	}
}

//////////////////////////////////////////////////////////////////////////////////////////
// Print thread message                                                                	//
// ==================================================================================== //
// Input  : void* -> Function pointer                  				        //
// Output : void* -> Function pointer			                                //
// Purpose: print message when thread is operating					//
//////////////////////////////////////////////////////////////////////////////////////////
void* thr_fn(void* message)
{
	printf("  * PID# %d create the * TID# %lu. \n", getpid(), pthread_self());
}
