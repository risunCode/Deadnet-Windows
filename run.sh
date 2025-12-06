#!/system/bin/sh
# DeadNet - Android Run Script (for KernelSU/Magisk)
# Usage: su -c "sh ~/deadnet/run.sh"

cd /data/data/com.termux/files/home/deadnet
export LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib
export PATH=/data/data/com.termux/files/usr/bin:$PATH
/data/data/com.termux/files/usr/bin/python main.py --browser
