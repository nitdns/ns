#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char charMap[26];
void updateMap(char *ptxt, char *ctxt)
{
    int strLen = strlen(ptxt);
    for (int i = 0; i < strLen; i++)
    {
        charMap[ptxt[i] - 'a'] = ctxt[i];
    }
}
void substitutionCipher(char *ptxt)
{
    int n = strlen(ptxt);
    char *ctxt = (char *)malloc(sizeof(char *) * n);
    for (int i = 0; i < n; i++)
    {
        ctxt[i] = charMap[ptxt[i] - 'a'];
    }
    ctxt[n] = '\0';
    printf("\n Ptxt: %s", ptxt);
    printf("\n Ctxt: %s\n", ctxt);
}
int main()
{
    updateMap("imaynotbeabletogrowflowersbutmygardenproduces", "EMGLOSUDCGDNCUSWYSFHNSFCYKDPUMLWGYICOXYSIPJCK");
    updateMap("justasmanydeadleavesoldovershoespiecesofropea", "QPKUGKMGOLICGINCGACKSNISACYKZSCKXECJCKSHYSXCG");
    substitutionCipher("imaynotbeabletogrowflowersbutmygardenproduces");
    substitutionCipher("justasmanydeadleavesoldovershoespiecesofropea");
    substitutionCipher("ndbushelsofdeadgrassasanybodysandtodayibought");
    substitutionCipher("awheelbarrowtohelpinclearingitupihavealwayslo");
    substitutionCipher("vedandrespectedthewheelbarrowitistheonewheele");
    substitutionCipher("dvehicleofwhichiamperfectmaster");
    return 0;
}