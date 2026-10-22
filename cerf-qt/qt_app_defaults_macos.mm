#include "qt_app_defaults.h"

#import <Foundation/Foundation.h>

/* Apple AppKit Release Notes for OS X 10.11, Full Screen: set the NSFullScreenMenuItemEverywhere
   default to NO before NSApplicationDidFinishLaunchingNotification is sent. */
void ApplyPlatformAppDefaults() {
    [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"NSFullScreenMenuItemEverywhere"];
}
