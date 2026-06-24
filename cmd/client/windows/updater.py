import sys, os
import zipfile
import time
from pathlib import Path

# launch "updater {zippath}"

current_name = os.path.basename(sys.executable)
current_dir = Path(sys.executable).parent

if len(sys.argv) <= 1:
    print('\n[e] Please provide zip file path')
    sys.exit(0)

if not zipfile.is_zipfile(sys.argv[1]):
    print('\n[e] Please provide zip file path')
    sys.exit(0)

with zipfile.ZipFile(sys.argv[1], 'r') as zf:
    time.sleep(0.5)
    for member in zf.infolist():
        memname = member.filename
        for attempt in range(3):
            try:
                if memname == current_name:
                    continue
                zf.extract(member, current_dir)
                print(f'[+] Replaced {memname}')
                break
            except PermissionError:
                time.sleep(1)
        else:
            print(f'[e] Can not replace {memname}')

os.remove(sys.argv[1])
print(f'[+] Replacing finished')
sys.exit(0)