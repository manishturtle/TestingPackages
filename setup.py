from setuptools import setup, find_packages

setup(
    name="ecomm-tenant",  # Package name (unique)
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "django>=3.2",
        "djangorestframework",
    ],
    license="MIT",
    description="Reusable Django DRF app for multi-tenant e-commerce",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="you@example.com",
    url="https://github.com/yourusername/ecomm-tenant",
    classifiers=[
        "Framework :: Django",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
