# FunKiiU

FunKiiU is a Python tool, compatible with Python 2.7 and 3, to download Wii U content from N's CDN.

  - It supports games, dlc, updates, virtual console, demos, **any** content.
  - By default DLC will be patched to unlock all pieces of DLC.
  - By default demos will be patched to remove any play count limits. *(does Wii U have this?)*


FunKiiU will accept keys and generate tickets, but you do not have to enter a key.
- You can choose to get the key automatically from **-thekeysite-**.
- Or, you can choose to get a legit ticket from **-thekeysite-** instead.
- **¡¡On first use, you will need to provide the url of -thekeysite-!!**
    - **Here is a hint** - https://encrypted.google.com/search?hl=en&q=wiiu%20title%20key%20site   

Using **keys** will generate a ticket that is not legit, the Wii U needs signature patches to accept it. (This is possible now, but a bit tricky to set up.)

Using **tickets** will download a ticket that is legit, and once installed, the content will work without any hacks at all. This is ideal, yet there are not and will not be tickets for **all** content that exists.

![running](http://i.imgur.com/YVsDqxE.png)

### Usage

To download Pikmin 3 EUR, by entering the Title ID and key:
```sh
$ python FunKiiU.py -title 000500001012be00 -key 32characterstitlekeyforpikmineur
```

To download Pikmin 3 EUR, by entering the Title ID and getting the key from **-thekeysite-**:
```sh
$ python FunKiiU.py -title 000500001012be00 -onlinekeys
```
To download Pikmin 3 EUR, by entering the Title ID and getting the ticket from **-thekeysite-**:
````sh
$ python FunKiiU.py -title 000500001012be00 -onlinetickets
````
Download multiple things, one after another - (can use with *-onlinekeys* or *-onlinetickets*):
````sh
$ python FunKiiU.py -title TITLEID1 TITLEID2 TITLEID3 -key KEY1 KEY2 KEY3
````
Downloads all content from **-thekeysite-**, all games, updates and dlc:
````sh
$ python FunKiiU.py -all
````
---
Content will be output to a folder with the Title ID, name (if using *-onlinekeys* or *-onlinetickets*), and type (DLC or update), within the **'install'** directory.
![output](http://i.imgur.com/U1n66Zj.png)

The downloaded output can then be installed using **wupinstaller**, or any similar tool.
