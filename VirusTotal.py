from virus_total_apis import PublicApi as VirusTotal

# Personal VirusTotal API key goes here
vt_api_key = ""
vt = VirusTotal(vt_api_key)

running = True
while running == True:
    # Submit hash to VT
    hash_value = input("Enter a hash value to submit to VT: ")
    report = vt.get_file_report(hash_value)

    # Count how many positive detections
    results = report['results']['scans']
    count = 0
    for detection in results:
        malicious = results[detection]
        if malicious['detected'] == True:
            count += 1

    # Print results
    print(results)
    print("Detections: ", count)
    if count > 0:
        print("Malicious File!")
    print('\n\n')

    # Try again?
    search_again = input("Enter another hash? (Y/N): ")
    search_again = search_again.lower()
    if search_again != 'y':
        exit()


