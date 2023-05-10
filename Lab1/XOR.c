#include<stdio.h>
#include<string.h>
int main(){

char* str="Hello World";
int i=0;
for(i=0;i<strlen(str);i++){
	printf("%c %d\n",str[i]^0,str[i]^0);
}
return 0;
}

