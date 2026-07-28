from modules.parser import parse_logs

dataframe = parse_logs(
    "logs/dns_logs.csv",
    schema="dns"
)

print(dataframe.head())

print()

print(dataframe.dtypes)
