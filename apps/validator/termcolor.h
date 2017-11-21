/***
 * Termcolor Copyright &copy; 2012
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * for more informations contact at <contact@cYounes.com>
 *
 * author: Younes Cheikh : cyounes@twitter | younes.cheikh{at}gmail{dot}com
 * Project Page: https://github.com/cyounes/termcolor
 */


/*
 * About: ANSII Color formatting for output in terminal.
 * Version: 0.2
 */

#ifndef _TERMCOLOR_H
#define _TERMCOLOR_H

#include <stdio.h>
#include <string.h>
#include <stdarg.h>


/*
 * Available colors
 */
typedef enum {
    BLACK,  /*!< number 0 */
    RED,    /*!< number 1 */
    GREEN,  /*!< number 2 */
    YELLOW, /*!< number 3 */
    BLUE,   /*!< number 4 */
    MAGENTA,/*!< number 5 */
    CYAN,   /*!< number 6 */
    WHITE,   /*!< number 7 */
    DEFAULT  /*!< number 8 */
}
_COLOR_ ;

/*
 * Type Boolean
 */
typedef enum {
    FALSE, /*!< Can be the integer 0 */
    TRUE  /*!< Can be the integer 1 */
}
BOOLEAN;

char    * START_BOLD ="${bd}",
* STOP_BOLD = "${/bd}",
* START_UNDERLINE ="${ul}",
* STOP_UNDERLINE = "${/ul}",
* START_BLINK ="${bl}",
* STOP_BLINK = "${/bl}",
* START_REVERSE ="${rv}",
* STOP_REVERSE = "${/rv}",
* START_BG_INTENSITY ="${bi}",
* STOP_BG_INTENSITY = "${/bi}",
* START_FG_INTENSITY ="${fi}",
* STOP_FG_INTENSITY = "${/fi}",
* START_BG ="${bg}", // Start background color
* STOP_BG = "${/bg}",  // Stop background color
* BLACK_BACKGROUND = "${bb}",
* RED_BACKGROUND = "${rb}",
* GREEN_BACKGROUND = "${gb}",
* YELLOW_BACKGROUND = "${yb}",
* BLUE_BACKGROUND = "${ub}",
* MAGENTA_BACKGROUND = "${mb}",
* CYAN_BACKGROUND = "${cb}",
* WHITE_BACKGROUND = "${wb}",
* START_FG ="${fg}", // Start background color
* STOP_FG = "${/fg}",  // Stop background color
* BLACK_FOREGROUND = "${bf}",
* RED_FOREGROUND = "${rf}",
* GREEN_FOREGROUND = "${gf}",
* YELLOW_FOREGROUND = "${yf}",
* BLUE_FOREGROUND = "${uf}",
* MAGENTA_FOREGROUND = "${mf}",
* CYAN_FOREGROUND = "${cf}",
* WHITE_FOREGROUND = "${wf}";

//char KEYWORDS[32][];
//= { START_BOLD , STOP_BOLD , START_UNDERLINE, STOP_UNDERLINE, START_BLINK, STOP_BLINK, START_REVERSE, STOP_REVERSE, START_BG_INTENSITY, STOP_BG_INTENSITY,START_FG_INTENSITY, STOP_FG_INTENSITY, START_BG, STOP_BG, BLACK_BACKGROUND, RED_BACKGROUND, GREEN_BACKGROUND, YELLOW_BACKGROUND, BLUE_BACKGROUND ,MAGENTA_BACKGROUND ,CYAN_BACKGROUND ,WHITE_BACKGROUND ,START_FG , STOP_FG , BLACK_FOREGROUND ,RED_FOREGROUND ,GREEN_FOREGROUND ,YELLOW_FOREGROUND ,BLUE_FOREGROUND ,MAGENTA_FOREGROUND ,CYAN_FOREGROUND ,WHITE_FOREGROUND };

//char KEYWORDS[3][10] ;

/*
 * Standard variables
 */
BOOLEAN _BOLD_TEXT=FALSE,
_HIGH_INTENSITY_FG=FALSE,
_HIGH_INTENSITY_BG=FALSE,
_UNDERLINE_TEXT=FALSE,
_BLINK_TEXT=FALSE,
_REVERSE_COLORS=FALSE;


int FGCOLOR, /*!< The forground chosed by the programer */
BGCOLOR; /*!< The background chosed by the programer */

BOOLEAN _CHANGE_FGCOLOR=FALSE, /*!< this will be set TRUE if you         call the FG_COLOR_ON() function */
_CHANGE_BGCOLOR=FALSE; /*!< this will be set TRUE if you call the           FG_COLOR_ON() function */
BOOLEAN _AUTO_RESET = FALSE;

/*
 * HEADERS
 */

void bgColor(_COLOR_ COLOR) ;

void fgColor(_COLOR_ COLOR) ;

void textBold(BOOLEAN status) ;

void textBlink(BOOLEAN status) ;

void colorReverse(BOOLEAN status);

void textUnderline(BOOLEAN status);

void highFgIntensity(BOOLEAN status) ;

void highBgIntensity(BOOLEAN status) ;

void setStyle() ;

void resetStyle() ;

void autoResetStyle(BOOLEAN autoReset) ;

BOOLEAN colorChanged(char * tmpString);

void cprint(const char* string, ...);


/*
 * FUNCTIONS
 */
void bgColor(_COLOR_ COLOR) {
	
	if (COLOR >=0 && COLOR <8 ) {
		BGCOLOR = (_HIGH_INTENSITY_BG==FALSE)?40:100 ;
		BGCOLOR = BGCOLOR + COLOR;
		_CHANGE_BGCOLOR = TRUE;
	}
	else {
		_CHANGE_BGCOLOR = FALSE;
	}
	setStyle();
}

void fgColor(_COLOR_ COLOR) {
	
	if (COLOR >=0 && COLOR <8 ) {
		FGCOLOR = (_HIGH_INTENSITY_FG==FALSE)?30:90;
		FGCOLOR = FGCOLOR + COLOR;
		_CHANGE_FGCOLOR = TRUE;
	}
	else {
		_CHANGE_FGCOLOR = FALSE;
	}
	setStyle();
}

void textBold(BOOLEAN status) {
    _BOLD_TEXT = status ;
    setStyle();
}

void textBlink(BOOLEAN status) {
	_BLINK_TEXT = status ;
	setStyle();
}

void colorReverse(BOOLEAN status) {
	_REVERSE_COLORS = status;
	setStyle();
}

void textUnderline(BOOLEAN status) {
	_UNDERLINE_TEXT = status ;
    setStyle();
}

void highFgIntensity(BOOLEAN status) {
	_HIGH_INTENSITY_FG = status;
	setStyle();
}

void highBgIntensity(BOOLEAN status) {
	_HIGH_INTENSITY_BG = status;
	setStyle();
}

void setStyle() {
	
	int conf[6];
	
	conf[0] = (_BLINK_TEXT == FALSE) ? 0 : 5 ;
	conf[1]  = (_BOLD_TEXT  == FALSE) ? 0 : 1 ;
	conf[2] = (_UNDERLINE_TEXT == FALSE ) ? 0 : 4 ;
	conf[3] = (_CHANGE_FGCOLOR == FALSE ) ? 0 : FGCOLOR ;
	conf[4] = (_CHANGE_BGCOLOR == FALSE ) ? 0 : BGCOLOR ;
	conf[5] = (_REVERSE_COLORS == FALSE ) ? 0 : 7 ;
	
	printf("\e[0m");
	int i ;
	for (i = 0 ; i< 6 ; i++)
	{
		if (conf[i] !=0 )
			printf("\e[%dm", conf[i]);
	}
}

void resetStyle() {
    _BLINK_TEXT = FALSE;
    _BOLD_TEXT = FALSE;
    _UNDERLINE_TEXT = FALSE;
    _REVERSE_COLORS = FALSE;
    FGCOLOR = DEFAULT ;
    BGCOLOR = DEFAULT ;
    _HIGH_INTENSITY_BG = FALSE;
    _HIGH_INTENSITY_FG = FALSE;
    setStyle();
}

void autoResetStyle(BOOLEAN autoReset) {
    _AUTO_RESET = autoReset;
}

BOOLEAN colorChanged(char * tmpString) {
	BOOLEAN retVal = FALSE;
	
	retVal = (strcmp(tmpString, START_BG) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, BLACK_BACKGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, RED_BACKGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, GREEN_BACKGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, YELLOW_BACKGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, BLUE_BACKGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, MAGENTA_BACKGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, CYAN_BACKGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, WHITE_BACKGROUND) == 0 ) ? TRUE : retVal ;
                    
                    //FOREGROUND COLOR
	retVal = (strcmp(tmpString, START_FG) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, BLACK_FOREGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, RED_FOREGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, GREEN_FOREGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, YELLOW_FOREGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, BLUE_FOREGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, MAGENTA_FOREGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, CYAN_FOREGROUND) == 0 ) ? TRUE : retVal ;
	retVal = (strcmp(tmpString, WHITE_FOREGROUND) == 0 ) ? TRUE : retVal ;
	return retVal;
}

void cprint(const char* string, ...) {
	va_list listPointer;
	va_start( listPointer, string );
    int i = 0 ,j;
    char tmpString[7];
    while (i < strlen(string)) {
		if (string[i] == '%' ) {
			if (string[i+1] == 'd') {
				printf("%d",va_arg( listPointer, int ));
				i=i+2;
			}
			else if (string[i+1] == 'c') {
				printf("%c",(char) va_arg( listPointer, int ));
				i=i+2;
			}
			else if (string[i+1] == 's') {
				char * subString = va_arg( listPointer, char * ) ;
				int nops = (int)strlen(subString) -1 ;
				printf("%s",subString);
				i=i+2;
			}
			else {	
				printf("%c",string[i]);
				i++;
			}
		}
        else if (string[i]=='$') {
            for (j=0; j<6;j++) {
                tmpString[j] = string[i+j];
            }
            if (tmpString[2] != '/') {
                tmpString[5] = '\0';
                // DECORATION
                if (strcmp(tmpString, START_BOLD) == 0 ) { textBold(TRUE); i=i+5; }
                else if (strcmp(tmpString, START_BLINK) == 0 ) { textBlink(TRUE); i=i+5; }
                else if (strcmp(tmpString, START_UNDERLINE) == 0 ) { textUnderline(TRUE); i=i+5; }
                else if (strcmp(tmpString, START_BG_INTENSITY) == 0 ) { highBgIntensity(TRUE); i=i+5; }
                else if (strcmp(tmpString, START_FG_INTENSITY) == 0  ) { highFgIntensity(TRUE); i=i+5; }
                else if (strcmp(tmpString, START_REVERSE) == 0 ) { colorReverse(TRUE); i=i+5; }
                else if (colorChanged(tmpString)==TRUE) {
                    
                    // BACKGROUND COLOR
                    BGCOLOR = (strcmp(tmpString, START_BG) == 0 ) ? DEFAULT : BGCOLOR ;
                    BGCOLOR = (strcmp(tmpString, BLACK_BACKGROUND) == 0 ) ? BLACK : BGCOLOR ;
                    BGCOLOR = (strcmp(tmpString, RED_BACKGROUND) == 0 ) ? RED : BGCOLOR ;
                    BGCOLOR = (strcmp(tmpString, GREEN_BACKGROUND) == 0 ) ? GREEN : BGCOLOR ;
                    BGCOLOR = (strcmp(tmpString, YELLOW_BACKGROUND) == 0 ) ? YELLOW : BGCOLOR ;
                    BGCOLOR = (strcmp(tmpString, BLUE_BACKGROUND) == 0 ) ? BLUE : BGCOLOR ;
                    BGCOLOR = (strcmp(tmpString, MAGENTA_BACKGROUND) == 0 ) ? MAGENTA : BGCOLOR ;
                    BGCOLOR = (strcmp(tmpString, CYAN_BACKGROUND) == 0 ) ? CYAN : BGCOLOR ;
                    BGCOLOR = (strcmp(tmpString, WHITE_BACKGROUND) == 0 ) ? WHITE : BGCOLOR ;
                    
                    //FOREGROUND COLOR
                    FGCOLOR = (strcmp(tmpString, START_FG) == 0 ) ? DEFAULT : FGCOLOR ;
                    FGCOLOR = (strcmp(tmpString, BLACK_FOREGROUND) == 0 ) ? BLACK : FGCOLOR ;
                    FGCOLOR = (strcmp(tmpString, RED_FOREGROUND) == 0 ) ? RED : FGCOLOR ;
                    FGCOLOR = (strcmp(tmpString, GREEN_FOREGROUND) == 0 ) ? GREEN : FGCOLOR ;
                    FGCOLOR = (strcmp(tmpString, YELLOW_FOREGROUND) == 0 ) ? YELLOW : FGCOLOR ;
                    FGCOLOR = (strcmp(tmpString, BLUE_FOREGROUND) == 0 ) ? BLUE : FGCOLOR ;
                    FGCOLOR = (strcmp(tmpString, MAGENTA_FOREGROUND) == 0 ) ? MAGENTA : FGCOLOR ;
                    FGCOLOR = (strcmp(tmpString, CYAN_FOREGROUND) == 0 ) ? CYAN : FGCOLOR ;
                    FGCOLOR = (strcmp(tmpString, WHITE_FOREGROUND) == 0 ) ? WHITE : FGCOLOR ;
                    
                    //APPLY NEW DECORE
                    bgColor(BGCOLOR);
                    fgColor(FGCOLOR);
					 i=i+5; 
                }
				else {
					printf("%c",string[i]);
					i++;
				}
            }
            else {
                if (strcmp(tmpString, STOP_BOLD) == 0 ) { textBold(FALSE); i=i+6; }
                else if (strcmp(tmpString, STOP_UNDERLINE) == 0 ) { textUnderline(FALSE); i=i+6; }
                else if (strcmp(tmpString, STOP_BLINK) == 0 ) { textBlink(FALSE); i=i+6; }
                else if (strcmp(tmpString, STOP_REVERSE) == 0 ) { colorReverse(FALSE); i=i+6; }
                else if (strcmp(tmpString, STOP_BG_INTENSITY) == 0 ) { highBgIntensity(FALSE); i=i+6; }
                else if (strcmp(tmpString, STOP_FG_INTENSITY) == 0 ) { highFgIntensity(FALSE); i=i+6; }
                else if (strcmp(tmpString, STOP_BG) == 0 ) { bgColor(DEFAULT); i=i+6; }
                else if (strcmp(tmpString, STOP_FG) == 0 ) { fgColor(DEFAULT); i=i+6; }
                else {
					printf("%c",string[i]);
					i++;
				}
            }
        }
        else {
            printf("%c",string[i]);
            i++;
        }
    }
    va_end( listPointer );
    if (_AUTO_RESET)
        resetStyle();
}



#endif
