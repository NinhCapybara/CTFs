import binascii
import calendar
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

# -----------------------------
# CONSTELLATION (32 DWORD)
# -----------------------------
constellation = [
    0x70, 0x44, 0xBD, 0xFB, 0x37, 0x80, 0x67, 0x7F,
    0x91, 0x00, 0x80, 0x52, 0xAA, 0x33, 0x10, 0x55,
    0x90, 0x04, 0xBB, 0xED, 0xEE, 0x77, 0x22, 0x66,
    0x11, 0x42, 0x88, 0xFF, 0xCC, 0x23, 0x19, 0x02
]

TARGET = 0xB2D50B77

stop_flag = False
stop_lock = threading.Lock()

progress_year = 0
total_checks = 0
progress_lock = threading.Lock()


# -----------------------------
# SHUFFLE LOGIC
# -----------------------------
def shuffle_array(day, month, year, fav):
    arr = constellation[:]  # copy

    key = day * month + year

    # Step 1
    for i in range(32):
        arr[i] = (arr[i] ^ key) & 0xFFFFFFFF

    # Step 2 rotate
    r = fav % 32
    if r:
        arr = arr[-r:] + arr[:-r]

    # Step 3 swaps
    s = (day + fav) % 32
    for i in range(32):
        j = (i + s) % 32
        arr[i], arr[j] = arr[j], arr[i]

    return arr


def crc32_of_array(arr):
    data = b''.join(x.to_bytes(4, 'little') for x in arr)
    return binascii.crc32(data) & 0xFFFFFFFF


# -----------------------------
# BRUTE FORCE 1 YEAR
# -----------------------------
def brute_year(year):
    global stop_flag, progress_year, total_checks

    local_checks = 0

    for month in range(1, 13):
        max_day = calendar.monthrange(year, month)[1]

        for day in range(1, max_day + 1):

            for fav in range(1, 100):
                if fav % 7 == 0:
                    continue

                # Stop if found
                with stop_lock:
                    if stop_flag:
                        return None

                arr = shuffle_array(day, month, year, fav)
                c = crc32_of_array(arr)

                local_checks += 1

                if c == TARGET:
                    with stop_lock:
                        stop_flag = True
                    return (day, month, year, fav)

    # Update global counters
    with progress_lock:
        progress_year += 1
        total_checks += local_checks

    return None


# -----------------------------
# PROGRESS DISPLAY THREAD
# -----------------------------
def progress_thread(start_time):
    while True:
        time.sleep(0.2)
        with stop_lock:
            if stop_flag:
                return

        with progress_lock:
            years_done = progress_year
            checks = total_checks

        elapsed = time.time() - start_time
        speed = checks / elapsed if elapsed > 0 else 0

        print(
            f"\r[+] Years done: {years_done}/(1990–3000) "
            f"| Speed: {speed/1e6:.2f}M ops/s "
            f"| Elapsed: {elapsed:.1f}s",
            end=""
        )


# -----------------------------
# MAIN
# -----------------------------
def main():
    print("[*] Multi-thread brute force started…")

    workers = os.cpu_count()
    print(f"[*] Using {workers} threads\n")

    start_time = time.time()

    # Start progress monitor
    t = threading.Thread(target=progress_thread, args=(start_time,), daemon=True)
    t.start()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []

        for y in range(1990, 3001):
            futures.append(executor.submit(brute_year, y))

        for f in as_completed(futures):
            result = f.result()
            if result is not None:
                day, month, year, fav = result
                print("\n\n==============================")
                print(">>> FOUND VALID INPUT <<<")
                print("==============================")
                print(f"Day:             {day}")
                print(f"Month:           {month}")
                print(f"Year:            {year}")
                print(f"Favorite Number: {fav}")
                elapsed = time.time() - start_time
                print(f"\nTotal time: {elapsed:.2f}s")
                print("==============================\n")
                return

    print("\nNo match found.")


if __name__ == "__main__":
    main()
