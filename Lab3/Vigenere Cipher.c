#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *encrypt(char *plainText, char *key, int keyLen)
{
    char *ans = (char *)malloc(sizeof(char) * strlen(plainText));
    int i;
    for (i = 0; i < strlen(plainText); i++)
    {
        if (plainText[i] == ' ')
        {
            ans[i] = ' ';
        }
        else
        {
            ans[i] = ((((plainText[i] - 65) + (key[i % keyLen] - 65)) % 26) + 65);
        }
    }
    ans[i] = '\0';
    return ans;
}

char *decrypt(char *encryption, char *key, int keyLen)
{
    char *ans = (char *)malloc(sizeof(char) * strlen(encryption));
    int i;
    for (i = 0; i < strlen(encryption); i++)
    {
        if (encryption[i] == ' ')
        {
            ans[i] = ' ';
        }
        else
        {
            ans[i] = ((((encryption[i] - 65) - (key[i % keyLen] - 65) + 26) % 26) + 65);
        }
    }
    ans[i] = '\0';
    return ans;
}

int main()
{
    char plainText[] = "SHE IS VERY HAPPY AND BEAUTIFUL GIRL";
    char key[] = "ANOTHER";
    int keyLen = strlen(key);
    char *encryption = encrypt(plainText, key, keyLen);
    char *decryption = decrypt(encryption, key, keyLen);
    printf("Plain message: %s\n", plainText);
    printf("Encrypted message: %s\n", encryption);
    printf("Decrypted message: %s\n", decryption);
    return 0;
}
