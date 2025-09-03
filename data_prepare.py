import random
import string
import pandas as pd
from faker import Faker
import math
from collections import Counter
from decimal import Decimal, getcontext
getcontext().prec = 3  # Set precision
import re

# Keywords commonly indicating secrets
key_patterns = [
    r"(?i)auth",          # auth, authorization
    r"(?i)token",         # token, access_token
    r"(?i)secret",        # secret, API_SECRET
    r"(?i)key",           # key, api_key
    r"(?i)password",      # password, mysql_password
    r"(?i)cred",          # credential, creds
    r"(?i)access",        # access key/id
    r"(?i)jwt",           # jwt tokens
    r"(?i)session",       # session tokens
    r"(?i)private",       # private_key, private key
    r"(?i)api[_-]?key",   # api_key, api-key
    r"(?i)client[_-]?secret",  # client_secret
    r"(?i)refresh[_-]?token",  # refresh_token
    r"(?i)bearer",        # Bearer token
    r"(?i)credential",    # generic credential
    r"(?i)certificate",   # certificate/SSL
    r"(?i)env",           # environment secrets
    r"(?i)passphrase",    # passphrase
]

# Context words indicating usage context
context_patterns = [
    r"(?i)db",            # database, db
    r"(?i)database",
    r"(?i)aws",           # Amazon Web Services
    r"(?i)github",        # GitHub
    r"(?i)api",           # API usage
    r"(?i)oauth",         # OAuth tokens
    r"(?i)config",        # configuration
    r"(?i)connection",    # connection string
    r"(?i)server",        # server host
    r"(?i)postgres",      # PostgreSQL
    r"(?i)mysql",         # MySQL
    r"(?i)mongo",         # MongoDB
    r"(?i)redis",
    r"(?i)cassandra",
    r"(?i)firebase",
    r"(?i)azure",
    r"(?i)gcp",           # Google Cloud
    r"(?i)heroku",
    r"(?i)stripe",
    r"(?i)paypal",
    r"(?i)twitter",
    r"(?i)slack",
    r"(?i)discord",
    r"(?i)linkedin",
    r"(?i)jwt",           # JWT context
    r"(?i)ssh",           # SSH keys
    r"(?i)ssl",           # SSL certificates
    r"(?i)keyvault",      # Azure Key Vault
    r"(?i)secretsmanager",# AWS Secrets Manager
    r"(?i)env",           # environment variable
]

def extract_keys_and_context(text):
    keys_found = []
    context_found = []
    
    for pattern in key_patterns:
        if re.search(pattern, text):
            keys_found.append(pattern.strip("(?i)"))  # store simple keyword
    
    for pattern in context_patterns:
        if re.search(pattern, text):
            context_found.append(pattern.strip("(?i)"))
    
    return (keys_found,context_found)
 
# Utility functions
def random_string(length=16, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(length))

def random_hex(length=40):
    return ''.join(random.choice("abcdef" + string.digits) for _ in range(length))

def random_base64(length=64):
    return ''.join(random.choice(string.ascii_letters + string.digits + "+/") for _ in range(length))

#Entropy calculation for a string

def calculate_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    """
    length = len(s)
    if length == 0:
        return 0.0

    freq_map = Counter(s)
    entropy = 0.0

    for count in freq_map.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def calculate_combinations(s: str) -> float:
    """
    Calculate approximate number of combinations for a string based on entropy.
    """
    entropy = calculate_entropy(s)
    return 2 ** (entropy * len(s))

def calculate_combinations_bigint(s: str) -> Decimal:
    """
    Calculate approximate number of combinations for a string based on entropy using Decimal for large numbers.
    """
    entropy = calculate_entropy(s)
    length = len(s)
    if length == 0:
        return Decimal(1)
    return Decimal(2) ** (Decimal(entropy) * Decimal(length))

# Secret generators - AWS credentials
def gen_aws_key():
    return "AKIA" + random_string(16).upper()

def gen_aws_secret():
    return "secret="+random_string(40, string.ascii_letters + string.digits + "/+=")

# def gen_aws_session_token():
#     return random_base64(100)

# Secret generators - GitHub tokens
def gen_github_token():
    return "ghp_" + random_string(36)

def gen_github_oauth():
    return "gho_" + random_string(36)

def gen_github_app_token():
    return "ghu_" + random_string(36)

# Secret generators - API authorization tokens
def gen_bearer_token():
    return f"Bearer {random_base64(40)}"

def gen_api_key():
    return f"api_key={random_string(32)}"

def gen_password():
    return f"password={random_string(random.randint(0, 16))}"

def gen_authorization_header():
    return f"Authorization: Bearer {random_base64(30)}"

# Secret generators - Database connection strings
def gen_mysql_password():
    return f"mysql_password={random_string(12)}"

def gen_db_connection_string():
    host = f"db-{random_string(8).lower()}.cluster.region.rds.amazonaws.com"
    username = random_string(8).lower()
    password = random_string(16)
    database = random_string(8).lower()
    return f"mysql://{username}:{password}@{host}/{database}"

def gen_mongo_uri():
    host = f"mongodb-{random_string(8).lower()}.mongo.cosmos.azure.com"
    username = random_string(8).lower()
    password = random_string(16)
    database = random_string(8).lower()
    return f"mongodb+srv://{username}:{password}@{host}/{database}?retryWrites=true&w=majority"

# Additional database generators - Relational
def gen_postgres_uri():
    host = f"postgres-{random_string(8).lower()}.postgres.database.azure.com"
    username = random_string(8).lower()
    password = random_string(16)
    database = random_string(8).lower()
    return f"postgresql://{username}:{password}@{host}/{database}"

def gen_mssql_connection_string():
    server = f"sql-{random_string(8).lower()}.database.windows.net"
    database = random_string(8).lower()
    user = random_string(8).lower()
    password = random_string(16)
    return f"Server={server};Database={database};User Id={user};Password={password};"

def gen_oracle_connection_string():
    host = f"oracle-{random_string(8).lower()}.oracle.com"
    service = random_string(8).upper()
    username = random_string(8).lower()
    password = random_string(16)
    return f"jdbc:oracle:thin:{username}/{password}@{host}:1521/{service}"

def gen_jdbc_mysql():
    host = f"mysql-{random_string(8).lower()}.mysql.database.azure.com"
    database = random_string(8).lower()
    username = random_string(8).lower()
    password = random_string(16)
    return f"jdbc:mysql://{host}:3306/{database}?user={username}&password={password}"

def gen_mariadb_connection():
    host = f"mariadb-{random_string(8).lower()}.mariadb.com"
    username = random_string(8).lower()
    password = random_string(16)
    database = random_string(8).lower()
    return f"mariadb://{username}:{password}@{host}/{database}"

def gen_sqlplus_command():
    username = random_string(8).lower()
    password = random_string(16)
    host = f"oracle-{random_string(8).lower()}.oracle.com"
    service = random_string(8).upper()
    return f"sqlplus {username}/{password}@{host}:1521/{service}"

# Additional database generators - NoSQL
def gen_redis_url():
    host = f"redis-{random_string(8).lower()}.redis.cache.windows.net"
    password = random_string(16)
    port = "6379"
    return f"redis://{random_string(8).lower()}:{password}@{host}:{port}"

def gen_cassandra_connection():
    host = f"cassandra-{random_string(8).lower()}.cassandra.cosmos.azure.com"
    username = random_string(8).lower()
    password = random_string(16)
    return f"cassandra_username={username}\ncassandra_password={password}\ncassandra_host={host}"

def gen_couchbase_uri():
    host = f"couchbase-{random_string(8).lower()}.couchbase.com"
    username = random_string(8).lower()
    password = random_string(16)
    return f"couchbase://{username}:{password}@{host}"

def gen_elasticsearch_connection():
    host = f"elastic-{random_string(8).lower()}.es.amazonaws.com"
    username = random_string(8).lower()
    password = random_string(16)
    return f"https://{username}:{password}@{host}:9200"

def gen_neo4j_connection():
    host = f"neo4j-{random_string(8).lower()}.graphdatabase.azure.com"
    username = random_string(8).lower()
    password = random_string(16)
    return f"neo4j://{username}:{password}@{host}:7687"

def gen_cosmosdb_connection():
    account = random_string(10).lower()
    key = random_base64(64)
    return f"AccountEndpoint=https://{account}.documents.azure.com:443/;AccountKey={key};"

def gen_dynamodb_credentials():
    access_key = random_string(20).upper()
    secret_key = random_string(40)
    return f"dynamodb_access_key_id={access_key}\ndynamodb_secret_access_key={secret_key}"

def gen_firestore_credentials():
    project_id = f"project-{random_string(8).lower()}"
    private_key_id = random_hex(40)
    private_key = random_string(64)
    return f'{{"project_id":"{project_id}","private_key_id":"{private_key_id}","private_key":"{private_key}"}}'

def gen_riak_connection():
    host = f"riak-{random_string(8).lower()}.riak.com"
    access_key = random_string(20)
    secret_key = random_string(40)
    return f"riak_host={host}\nriak_access_key={access_key}\nriak_secret_key={secret_key}"

def gen_hbase_connection():
    host = f"hbase-{random_string(8).lower()}.hbase.com"
    username = random_string(8).lower()
    password = random_string(16)
    return f"hbase.zookeeper.quorum={host}\nhbase.username={username}\nhbase.password={password}"

# Secret generators - JWT tokens
def gen_jwt():
    header = random_base64(16)
    payload = random_base64(32)
    signature = random_base64(32)
    return f"{header}.{payload}.{signature}"

# Secret generators - Cloud service credentials
def gen_azure_connection_string():
    account = random_string(10).lower()
    key = random_base64(64)
    return f"DefaultEndpointsProtocol=https;AccountName={account};AccountKey={key};EndpointSuffix=core.windows.net"

def gen_gcp_api_key():
    return f"AIza{random_string(35)}"

# def gen_heroku_api_key():
#     return random_hex(32)

# Secret generators - Private keys and connection strings
def gen_ssh_private_key():
    return f"""-----BEGIN RSA PRIVATE KEY-----
{random_base64(64)}
{random_base64(64)}
{random_base64(64)}
{random_base64(32)}
-----END RSA PRIVATE KEY-----"""

def gen_firebase_private_key():
    project_id = f"firebase-{random_string(8).lower()}"
    private_key_id = random_hex(40)
    private_key = f"-----BEGIN PRIVATE KEY-----\\n{random_base64(64)}\\n-----END PRIVATE KEY-----\\n"
    return f'{{"project_id":"{project_id}","private_key_id":"{private_key_id}","private_key":"{private_key}"}}'

# Certificate and SSL key generators
def gen_ssl_private_key():
    return f"""-----BEGIN PRIVATE KEY-----
{random_base64(64)}
{random_base64(64)}
{random_base64(32)}
-----END PRIVATE KEY-----"""

def gen_certificate_content():
    return f"""-----BEGIN CERTIFICATE-----
{random_base64(64)}
{random_base64(64)}
{random_base64(32)}
-----END CERTIFICATE-----"""

# Payment service secrets
def gen_stripe_api_key():
    return f"sk_live_{random_string(24)}"

def gen_stripe_publishable_key():
    return f"pk_live_{random_string(24)}"

def gen_paypal_client_id():
    return f"AYS{random_string(14).upper()}"

# def gen_paypal_client_secret():
#     return random_string(32)

def gen_credit_card():
    cc_types = ["4111111111111111", "5555555555554444", "378282246310005"]
    base = random.choice(cc_types)
    expiry = f"{random.randint(1, 12):02d}/{random.randint(23, 30)}"
    cvv = f"{random.randint(100, 999)}"
    return f"{base} {expiry} {cvv}"

# Social media API tokens
def gen_twitter_api_key():
    return f"{random_string(25)}"

def gen_twitter_api_secret():
    return f"{random_string(50)}"

def gen_facebook_app_token():
    return f"{random.randint(100000, 999999)}|{random_hex(32)}"

def gen_instagram_access_token():
    return f"IGQ{random_string(32)}"

# def gen_linkedin_client_secret():
#     return random_string(32)

# Webhook URLs
def gen_slack_webhook():
    workspace = random_string(8).lower()
    token_part = random_string(24)
    return f"https://hooks.slack.com/services/{workspace}/{token_part}/{random_string(24)}"

def gen_discord_webhook():
    channel_id = ''.join(random.choice(string.digits) for _ in range(18))
    token = random_string(68)
    return f"https://discord.com/api/webhooks/{channel_id}/{token}"

# def gen_twilio_auth_token():
#     return random_hex(32)

def gen_twilio_sid():
    return f"AC{random_string(32)}"

# Mobile services
def gen_apns_key():
    return f"""-----BEGIN PRIVATE KEY-----
{random_base64(64)}
{random_base64(32)}
-----END PRIVATE KEY-----"""

# def gen_fcm_server_key():
#     return random_string(40)

def gen_mobile_signing_key():
    return f"""-----BEGIN ANDROID KEY-----
{random_base64(64)}
-----END ANDROID KEY-----"""

# # Cryptocurrency
# def gen_wallet_private_key():
#     return random_hex(64)

def gen_mnemonic():
    words = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", 
             "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
             "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual"]
    return " ".join(random.sample(words, 12))

def gen_crypto_api_key():
    return f"{random_string(8)}-{random_string(8)}-{random_string(8)}-{random_string(8)}"

# Secret generators - OAuth tokens
def gen_oauth_token():
    return f"oauth_token={random_string(40)}"

def gen_refresh_token():
    return f"refresh_token={random_string(40)}"

def gen_access_token():
    return f"access_token={random_string(40)}"

# Secret generators - Environment variables
def gen_env_variable():
    env_vars = [
        f"MYSQL_PASSWORD={random_string(16)}",
        f"AWS_SECRET_ACCESS_KEY={random_string(40)}",
        f"GITHUB_TOKEN={random_string(40)}",
        f"API_KEY={random_string(32)}",
        f"JWT_SECRET={random_string(32)}",
        f"ENCRYPTION_KEY={random_hex(32)}"
    ]
    return random.choice(env_vars)

def gen_pat_token():
    return "pat_" + random_string(30)

def gen_sat_token():
    return "sat_" + random_hex(24)

# Non-secret examples
def gen_normal_text():
    samples = [
        "hello world",
        "this is not a secret",
        "contact me at test@example.com",
        "the value is 123456",
        "config setting enabled=true",
        "random notes about a project",
        "secret",
        "token",
        "password",
        "code",
        "data",
        "information",
        "dummy text",
        "sample data for testing",
        "no sensitive info here",
        "just some random words",
        "please configure the settings properly",
        "check documentation for more details",
        "make sure to update before proceeding",
    ]
    return random.choice(samples)

def gen_noisy_non_secret():
    fake = Faker()
    
    # Create more fake tokens with specific keywords
    fake_indicator_words = ['test', 'sample', 'example', 'dummy', 'fake', 'mock', 'demo', 
                           'placeholder', 'development', 'sandbox', 'trial', 'simulation',
                           'local', 'testing', 'temporary', 'notreal', 'invalid']
    
    # Generate more complex fake tokens using Faker
    samples = [
        "ghp_testtoken12345",  # looks like GitHub token
        "jwt_header.payload.signature",  # fake JWT
        "mysql_password=notasecret",  # fake config
        "pat_token_sample",  # PAT-like
        "satellite_token",  # SAT-like
        "AKIAEXAMPLEKEY1234",  # AWS-like but fake
        "password=flower",  # looks like password but normal
        "this is just a token of appreciation",  # natural language
        "debug_mode=true",
        "retry_count=3",
        "config_path=/usr/local/bin",
        "Lorem ipsum dolor sit amet",
        "api_key=TEST_KEY",
        "Bearer dummytoken",
        "Authorization header: Bearer sampletoken",
        "mongo_uri=mongodb://localhost:27017",
        "connection_string=Server=localhost;Database=test",
        "oauth_token=placeholder",
        "firebase_key=demo",
        "DEMO_API_KEY=test123",
        "ENV_VAR=test",
        # Generate additional samples using Faker and indicator words
        f"ghp_{random.choice(fake_indicator_words)}_{fake.bothify(text='???????###')}",
        f"pat_{random.choice(fake_indicator_words)}_{fake.bothify(text='?????####')}",
        f"Bearer {random.choice(fake_indicator_words)}_{fake.hexify(text='^^^^^^')}",
        f"api_key={random.choice(fake_indicator_words).upper()}_{fake.bothify(text='???###')}",
        f"AKIA{random.choice(fake_indicator_words).upper()}{fake.bothify(text='####????')}",
        f"mysql_password={random.choice(fake_indicator_words)}_{fake.word()}",
        f"secret={random.choice(fake_indicator_words)}_{fake.word()}",
        f"sat_{random.choice(fake_indicator_words)}_{fake.bothify(text='??????###')}",
        f"jwt_{fake.word()}.{fake.word()}.{fake.word()}",
        f"SAMPLE_ACCESS_KEY_{fake.bothify(text='???###')}",
        f"EXAMPLE_SECRET_{fake.hexify(text='??????')}",
        f"test_connection_string=Server={fake.domain_name()};Database=test;",
        f"mock_firebase_key={fake.md5()[:12]}",
        f"demo_token={fake.hexify(text='^^^^^^^^')}",
        f"Authorization: {random.choice(fake_indicator_words)} {fake.uuid4()}",
        f"mongo_uri=mongodb://{random.choice(fake_indicator_words)}@localhost:27017",
        f"DEV_{fake.word().upper()}_KEY={fake.bothify(text='????####')}",
        f"SANDBOX_TOKEN_{fake.hexify(text='^^^^')}",
        f"test.private.key.{fake.bothify(text='????####')}",
        f"-----BEGIN {random.choice(fake_indicator_words).upper()} KEY-----",
        f"connection_string=Server={random.choice(fake_indicator_words)}.example.com;",
        f"password={fake.word()}_{random.choice(fake_indicator_words)}",
        f"{random.choice(fake_indicator_words)}_access_token={fake.md5()[:16]}"
    ]
    return random.choice(samples)

# Generate secrets embedded in log-like lines
def gen_secret_in_logs():
    templates = [
        "INFO: connecting with mysql_password={}",
        "DEBUG: Authorization: Bearer {}",
        "WARN: Using API key {} in request",
        "export GITHUB_TOKEN={}",
        "jwt={}",
        "aws_secret={}",
        "API request with key: {}",
        "Connection established with connection_string={}",
        "New OAuth token generated: {}",
        "Using GCP credentials: {}",
        "Azure connection: {}"
    ]
    
    secret_gens = [
        lambda: gen_mysql_password().split("=")[1],
        lambda: gen_github_token(),
        lambda: gen_pat_token(),
        lambda: gen_jwt(),
        lambda: gen_aws_secret(),
        lambda: gen_api_key().split("=")[1],
        lambda: gen_mongo_uri().split("@")[1].split("/")[0],
        lambda: gen_oauth_token().split("=")[1],
        lambda: gen_gcp_api_key(),
        lambda: gen_azure_connection_string().split(";")[2].split("=")[1]
    ]
    
    template = random.choice(templates)
    secret_gen = random.choice(secret_gens)
    return template.format(secret_gen())

# Generate secrets embedded in normal text
def gen_secret_in_normal_text():
    fake = Faker()
    secret_gens = [
        gen_mysql_password,
        gen_github_token,
        gen_pat_token,
        gen_jwt,
        gen_aws_key,
        gen_aws_secret,
        gen_bearer_token,
        gen_api_key,
        gen_mongo_uri,
        gen_oauth_token,
        gen_env_variable,
        gen_gcp_api_key,
        gen_password
    ]
    secret = random.choice(secret_gens)()
    return f"{fake.word()} {secret} {fake.word()}"


def gen_non_faker_text():
    fake = Faker()
    return f"{fake.word()}"

def gen_hard_negative():
    samples = [
        "export GITHUB_TOKEN=placeholder",
        "jwt=header.payload.signature",
        "mysql_password=notasecret",
        "DEBUG: Authorization: Bearer sampletoken",
        "aws_secret=example123456",
        "pat_dummy_token",
        "token=test",
        "api_key=DEMO_KEY_123",
        "connection_string=Server=example;Database=test;Uid=demo;Pwd=placeholder;",
        "oauth_token=EXAMPLE_TOKEN",
        "refresh_token=DEMO_REFRESH",
        "AZURE_CONNECTION=placeholder",
        "GCP_CREDENTIALS=demo_only",
        "MONGODB_URI=mongodb://localhost:27017",
        "ACCESS_KEY=test_key_only"
    ]
    return random.choice(samples)

# Generate code-like examples with secrets
def gen_code_with_secret():
    code_templates = [
        'const apiKey = "{}";',
        'password = "{}"',
        'aws_access_key_id="{}"',
        'github_token="{}"',
        'db_connection = "{}";',
        'var jwtToken = "{}";',
        'azure_key="{}"',
        'private static final String API_KEY = "{}";',
        'oauth_token = "{}"',
        'environment.put("PASSWORD", "{}");'
    ]
    
    secret_gens = [
        lambda: random_string(32),
        lambda: random_string(16),
        lambda: gen_aws_key(),
        lambda: gen_github_token(),
        lambda: gen_db_connection_string(),
        lambda: gen_jwt(),
        lambda: random_string(32),
        lambda: random_string(32),
        lambda: random_string(40),
        lambda: random_string(16)
    ]
    
    template = random.choice(code_templates)
    secret_gen = random.choice(secret_gens)
    return template.format(secret_gen())

# Build dataset with balanced examples
def build_dataset(n=1000, ratio=0.5):
    data = []
    
    # All secret generators
    secret_generators = [
        # AWS
        gen_aws_key,
        gen_aws_secret,
        # gen_aws_session_token,
        
        # GitHub
        gen_github_token,
        gen_github_oauth,
        gen_github_app_token,
        
        # API tokens
        gen_bearer_token,
        gen_api_key,
        gen_authorization_header,

        #Passwords
        gen_password,

        
        # Database - Relational
        gen_mysql_password,
        gen_db_connection_string,
        gen_postgres_uri,
        gen_mssql_connection_string,
        gen_oracle_connection_string,
        gen_jdbc_mysql,
        gen_mariadb_connection,
        gen_sqlplus_command,
        
        # Database - NoSQL
        gen_mongo_uri,
        gen_redis_url,
        gen_cassandra_connection,
        gen_couchbase_uri,
        gen_elasticsearch_connection,
        gen_neo4j_connection,
        gen_cosmosdb_connection,
        gen_dynamodb_credentials,
        gen_firestore_credentials,
        gen_riak_connection,
        gen_hbase_connection,
        
        # JWT
        gen_jwt,
        
        # Cloud
        gen_azure_connection_string,
        gen_gcp_api_key,
        # gen_heroku_api_key,
        
        # Private keys
        gen_ssh_private_key,
        gen_firebase_private_key,
        
        # Certificate and SSL keys
        gen_ssl_private_key,
        gen_certificate_content,
        
        # Payment services
        gen_stripe_api_key,
        gen_stripe_publishable_key,
        gen_paypal_client_id,
        # gen_paypal_client_secret,
        gen_credit_card,
        
        # Social media
        gen_twitter_api_key,
        gen_twitter_api_secret,
        gen_facebook_app_token,
        gen_instagram_access_token,
        # gen_linkedin_client_secret,
        
        # Webhooks
        gen_slack_webhook,
        gen_discord_webhook,
        # gen_twilio_auth_token,
        gen_twilio_sid,
        
        # Mobile services
        gen_apns_key,
        # gen_fcm_server_key,
        gen_mobile_signing_key,
        
        # Cryptocurrency
        # gen_wallet_private_key,
        gen_mnemonic,
        gen_crypto_api_key,
        
        # OAuth
        gen_oauth_token,
        gen_refresh_token,
        gen_access_token,
        
        # Environment variables
        gen_env_variable,
        
        # Legacy generators
        gen_pat_token,
        gen_sat_token,
        
        # Contextual examples
        gen_secret_in_logs,
        gen_secret_in_normal_text,
        gen_code_with_secret
    ]
    
    # Non-secret generators
    non_secret_generators = [
        gen_normal_text,
        gen_noisy_non_secret,
        gen_hard_negative,
        gen_non_faker_text
    ]
    
    num_secrets = int(n * ratio)
    num_normals = n - num_secrets
    
    # Generate secrets
    for _ in range(num_secrets):
        gen = random.choice(secret_generators)
        secret = gen()
        key_word, context= extract_keys_and_context(secret)  # Just to ensure it runs without error
        data.append((secret, 1,calculate_entropy(secret),calculate_combinations_bigint(secret),"~".join(key_word),"~".join(context)))  # 1 = secret
    
    # Generate non-secrets
    for _ in range(num_normals):
        gen = random.choice(non_secret_generators)
        secret = gen()
        key_word, context= extract_keys_and_context(secret)  # Just to ensure it runs without error
        data.append((secret, 0,calculate_entropy(secret),calculate_combinations_bigint(secret),"~".join(key_word),"~".join(context))) # 0 = non secret
    
    random.shuffle(data)
    return pd.DataFrame(data, columns=["text", "label","entropy","combinations","key_indicators","context_indicators"])

# Example usage
if __name__ == "__main__":
    df = build_dataset(n=10000, ratio=0.5)
    print(df.sample(20))
    df.to_csv("synthetic_secret_dataset.csv", index=False)
    print("✅ Dataset saved as synthetic_secret_dataset.csv")