#!/system/bin/sh
cd /data/data/com.termux/files/home/deadnet
export LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib
export PATH=/data/data/com.termux/files/usr/bin:$PATH
exec /data/data/com.termux/files/usr/bin/python main.py --browser
