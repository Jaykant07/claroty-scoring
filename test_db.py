import sqlite3

def test():
    conn = sqlite3.connect('c:/Users/Jaykant/Desktop/claroty/claroty.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, ip, protocols, purdue_level FROM assets")
    rows = cursor.fetchall()
    
    empty_count = 0
    full_count = 0
    purdue_3_count = 0
    for r in rows:
        if r[2] == '' or r[2] is None:
            empty_count += 1
        else:
            full_count += 1
            print("Populated Protocol:", r)
            
        if r[3] == 3:
            purdue_3_count += 1
            
    print(f"Empty protocols: {empty_count}")
    print(f"Populated protocols: {full_count}")
    print(f"Purdue Level 3: {purdue_3_count}")

test()
