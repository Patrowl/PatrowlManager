from cpe import CPE


def extract_cpe(cpe_vector):
    """Extract vendor and product strings from CPE vector."""
    vendor = None
    product = None

    try:
        c = CPE(cpe_vector)
        vendor = c.get_vendor()[0]
        product = c.get_product()[0]
        # print("-->", c, vendor, product)
    except Exception as e:
        print(cpe_vector, e)

    return vendor, product
