# FunKiiU
Download content for Wii U


This will download things from CDN.

If you wanted to download Pikmin 3 EUR, you could use:

`python FunKiiU.py -title 000500001012be00 -key 32characterstitlekeyforpikmineur`

which gives you everything you need to install and play

**you will need signature patches to play this**

or

`python FunKiiU.py -title 000500001012be00 -onlinekeys`

which gives you everything, taking the key from *theykeysite*, if the key exists

**you will need signature patches to play this**

or

`python FunKiiU.py -title 000500001012be00 -onlinetickets`

which gives everything with one of those 'brazil' tickets, downloaded from *theykeysite*, if it exists. 

this ticket is basically a legit ticket so once installed:

**the game will work without hacks**


If desired you can also install to a custom directory using the -outputdir tag. This makes it more convinient to determine what title the files go to. Using the above example you would do this:

`python FunKiiU.py -outputdir pikmin_3 -title 000500001012be00 -onlinetickets`

**this will install the files to /install/pikmin_3**