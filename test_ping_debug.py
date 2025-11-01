import subprocess
import re
import platform

def test_ping_detailed(host):
    print(f"\n{'='*60}")
    print(f"Testing ping to: {host}")
    print(f"{'='*60}")
    
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output(
                ["ping", "-n", "1", "-w", "1000", host],
                stderr=subprocess.STDOUT, 
                text=True
            )
            
            print("RAW OUTPUT:")
            print(result)
            print(f"\n{'='*60}")
            
            # Test the regex pattern from the script
            m = re.search(r"Average = (\d+)ms", result)
            print(f"Regex match result: {m}")
            if m:
                print(f"Matched value: {m.group(1)}")
                print(f"Converted to int: {int(float(m.group(1)))}")
            else:
                print("⚠️ Regex did NOT match!")
                
                # Try alternative patterns
                print("\nTrying alternative patterns:")
                
                # Pattern 1: time= in reply line
                m1 = re.search(r"time=(\d+)ms", result)
                print(f"Pattern 'time=(\\d+)ms': {m1.group(1) if m1 else 'NO MATCH'}")
                
                # Pattern 2: time< in reply line (for <1ms)
                m2 = re.search(r"time<(\d+)ms", result)
                print(f"Pattern 'time<(\\d+)ms': {m2.group(1) if m2 else 'NO MATCH'}")
                
                # Pattern 3: Any number before ms
                m3 = re.findall(r"(\d+)ms", result)
                print(f"All numbers before 'ms': {m3}")
                
    except subprocess.CalledProcessError as e:
        print(f"❌ Ping failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

# Test with multiple hosts
test_ping_detailed("8.8.8.8")
test_ping_detailed("192.168.31.121")  # Replace with your actual IP
