*Tired of updating dynamic IP addresses?*
<br>*Internet provider won't give you a static IP?*
<br>***Have data you don't want routing through a tunnel or domain provider?***

# **DinoSync**
A simple group IP address synchronization tool.

## Client Setup
Anybody who wants to join a DinoSync group (as a client) only needs the `DinoSync.exe` file.
<br>Just copy/paste the program to any location and run it. A new `config.json` file will be created on the first launch.

You'll need to set an ID for yourself on the first line. 
On the second line, enter the group key. This must match the server's group key to allow synchronization.

> [!IMPORTANT]
> DinoSync will refuse to start unless you set an ID and group key.

DinoSync can also send notifications to the system tray. If you'd like to unmute these, set the value to false.

The sync and broadcast port values should be set according to your group host's config. These cannot be the same port.
<br>The `SYNC_HOST` argument is the domain or address on which your group's server is accessible.

> [!IMPORTANT]
> You MUST port-forward the `BROADCAST_PORT` value (TCP) to whichever machine is running the DinoSync client.

> [!TIP]
> It's also a good idea to make a shortcut of the program and put it in the startup folder.

You can also specify the time at which you'd like DinoSync to perform a handshake with the server. (Default: noon)

## Client Usage
Once the client daemon starts, it will make an initial attempt to contact the server in its config file. 
If the first attempt fails (or a scheduled attempt fails), it will automatically retry in 10 seconds. During this window, the icon will turn yellow.

If the second attempt fails, or if a manual refresh fails, the icon will turn red.

If the initial connection(s) didn't go through, or if you'd like to force-refresh your copy of the group database, right click the icon to open the GUI and click `Refresh Now`.

Upon a successful handshake with the server, the icon will turn green, and the GUI will show your group's IP database. You can click on any member's entry to quickly copy their IP address to the clipboard.

## Server Setup
If you want to run your own DinoSync group, you'll need the `DinoSyncServer.exe` file.
Regardless of where this program is placed, the `_interal` folder needs to be in the same directory.

On the first launch (or if it's missing), the server will create a new config file.
> [!IMPORTANT]
> DinoSync will refuse to start without a group key.
> <br>Whatever you enter for your group's secret key will need to be in your client configs as well.

The server host will need either a static IP address or tunnel for the clients to connect to. 
<br>**The server domain is not required in the server's config, only the port.**

> [!WARNING]
> DinoSync mimics Command-and-Control (C2) traffic.
> <br>If you use a tunnel service to host DinoSync, review the terms and conditions before starting.

The `HOST` argument in the server config should generally be left alone. `0.0.0.0` just means the server will listen for activity on all network devices.

Here's a breakdown of the port arguments:

| **Server Config**            | **Client Config**    | **Note**                                                                                                                                      |
|------------------------------|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `SYNC_PORT`                         | `SYNC_PORT`            | Port that clients will use to sync their information with the server. **This is the port used on your public-facing domain.** (Default: `59294`)   |
| `BROADCAST_PORT` | `BROADCAST_PORT` | Port that clients will listen on for new database broadcasts. **This is the port that clients will port-forward.** (Default: `59295`) |

The `MAX_CONNECTIONS` argument is basically how long you want your handshake queue to be. 
If multiple clients are trying to synchronize their databases simultaneously, this number is how many people can connect at the same time before the server starts refusing connections. 

You shouldn't need to increase this value if you have a smaller group, or if everybody is syncing at different times.
Increasing this value will make clients less likely to retry connection attempts, at the expense of using more resources.

## Server Usage
If you're hosting the server for your group, you should run the server and client daemons on separate machines.

You can right-click the icon to see your current database entries and the most recent handshake.
On the server GUI, clicking on an entry will remove it from the database. 
Clients will see the updated list on their next handshake.

> [!TIP]
> If you'd like to see the network activity as it occurs, click the `Restart in Debug Mode` option to get access to a command line output.
