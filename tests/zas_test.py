# -*- coding: utf-8 -*-


if __name__ == '__main__':
    from app import initialize, domain
    colony = domain.Colony.create_with_id(4)
    print(colony.calculate_raw_resources_extraction(10000))
