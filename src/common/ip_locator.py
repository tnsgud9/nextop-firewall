import os
import geoip2.database


db_path = os.path.join(os.path.dirname(__file__), "GeoLite2-Country.mmdb")


def find_country_code(ip_address):
    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip_address)
            return response.country.iso_code  # 국가 코드 (예: 'US', 'KR')
    except:
        return "N/A"
