/*
 * =====================================================================================
 *
 *       Filename:  test.c
 *
 *    Description:  Basic test.c file to run tests
 *
 *        Version:  1.0
 *        Created:  06/04/2020 04:57:00 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>

int main() {
    int number = 2;
    char vart[] = "Hello gordon!\n";
    char buff[10];
    printf("Do your thing\n");
    scanf("%s",&buff);
    if ( number == 2) {
        printf("%s",vart);
    } else {
        printf("There is no good thing at all.\n");
    }
    number = 3;
    printf("Try it again\n");
    scanf("%s",&buff);
    if (number == 3) {
        printf("%s",vart);
    } else {
        printf("You failed\n");
    }
}
