def load_blacklist(filepath='blacklist/ip_blacklist.txt'):
    with open(filepath) as f:
        return set(line.strip() for line in f)

def export_incidents(df, output='reports/incidents.csv'):
    df.to_csv(output, index=False)
