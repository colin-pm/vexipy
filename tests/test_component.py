from vexipy.component import Product, Subcomponent


def test_update_subcomponent():
    s = Subcomponent()
    s = s.update(hashes={"md5": "d41d8cd98f00b204e9800998ecf8427e"})
    assert s.hashes["md5"] == "d41d8cd98f00b204e9800998ecf8427e"


def test_update_product():
    c = Product()
    c = c.update(hashes={"md5": "d41d8cd98f00b204e9800998ecf8427e"})
    assert c.hashes["md5"] == "d41d8cd98f00b204e9800998ecf8427e"


def test_append_subcomponent():
    c = Product()
    s = Subcomponent()
    assert c.append_subcomponents(s)


def test_extend_subcomponent():
    c = Product()
    s = [Subcomponent() for _ in range(3)]
    assert c.extend_subcomponents(s)
