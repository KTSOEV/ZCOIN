# ZCOIN


<a href="https://www.buymeacoffee.com/ktsoev" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

Just a really simple, insecure and incomplete implementation of a blockchain for a cryptocurrency made in Python. The goal of this project is to make a working blockchain currency, keeping it as simple as possible and to be used as educational material.

>This project is just being made for fun. If you want to make your own cryptocurrency you should probably take a look at the [Bitcoin Repository](https://github.com/bitcoin/bitcoin).


## What is a blockchain?

Taking a look at the [Bitcoin organization wiki website](https://en.bitcoin.it/wiki/Main_Page) we can find this definition:

>A block chain is a transaction database shared by all nodes participating in a system based on the Bitcoin protocol. A full copy of a currency's block chain contains every transaction ever executed in the currency. With this information, one can find out how much value belonged to each address at any point in history.

In simpler terms, blockchain can be seen as a distributed ledger recording each transaction in the network. Each transaction is identified by the public key of the block which is a hash function of the private key. The distributed ledger makes data manipulation in the blockchain difficult, nearly impossible. 

You can find more information in the original [Bitcoin Paper](https://bitcoin.org/bitcoin.pdf).

## How to run it

First, install ```requirements.txt```.

```
pip install -r requirements.txt
```

Then you have 2 options:

- Run ```miner.py``` to become a node and start mining
- Run ```wallet.py``` to become a user and send transactions (to send transactions you must run a node, in other words, you must run ```miner.py``` too)

> Important: DO NOT run it in the python IDLE, run it in your console. The ```miner.py``` uses parallel processing that doesn't work in the python IDLE.

## How this code work?

There are 3 main scripts:

- ```miner.py```
- ```wallet.py```
- ```server.py```

### Server.py

This file is probably the most important. Running it will create a node (like a server). From here you can connect to the blockchain and process transactions (that other users send) by mining. As a reward for this work, you recieve some coins. The more nodes exist, the more secure the blockchain gets.

The following flowchart provides a simple , high-level understanding of what the miner does
![MinerFlowchart](images/flowchart.png)

### Wallet.py

This file is probably the most important. By running it, you will create a node (for example, a server). From here you can connect to the blockchain, and you can process transactions (which other users send) by mining thanks to the miner.py file. As a reward for this work, you receive coins. The more nodes there are, the more secure the blockchain becomes.

![wallet](https://k60.kn3.net/6/F/E/3/8/2/887.png)


## Contribution

Anybody is welcome to collaborate in this project. Feel free to push any pull request (even if you are new to coding). See ```CONTRIBUTING.md``` to learn how to contribute.

Note: the idea of this project is to build a **really simple** blockchain system, so make sure all your code is easy to read (avoid too much code in 1 line) and don't introduce complex updates if they are not critical. In other words, keep it simple.


## Disclaimer

By no means this project should be used for real purposes, it lacks security and may contain several bugs.
