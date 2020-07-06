const dotenv = require('dotenv')
const express = require('express')
const crypto = require('crypto')
const cookie = require('cookie')
const nonce = require('nonce')
const querystring = require('querystring')
const request = require('request-promise')
const ShopifyToken = require('shopify-token')
const rawBody = require('raw-body')
const bodyParser = require('body-parser')

dotenv.config()
const { apiKey, apiSecretKey } = process.env
const scope = 'write_products'
const forwardingAddress = "https://1e48686efed7.ngrok.io"

const shopifyToken = new ShopifyToken({
    sharedSecret: apiSecretKey,
    redirectUri: forwardingAddress + '/shopify/callback',
    apiKey: apiKey
})

const app = express()
app.use(bodyParser.json())

app.get('/shopify', (req, res) => {
    const shop = req.query.shop

    if(shop) {
        const state = shopifyToken.generateNonce()
        const redirectUri = forwardingAddress + '/shopify/callback'
        const installUrl = 'https://' + shop + '/admin/oauth/authorize?client_id=' + apiKey + '&scope=' + scope + '&state=' + state + '&redirect_uri=' + redirectUri

        res.cookie('state', state)
        res.redirect(installUrl)
    } else {
        return res.status(400).send('missing shop parameter ')
    }
})

app.get('/shopify/callback', (req, res) => {
    const { shop, hmac, code, state }  = req.query
    const stateCookie = cookie.parse(req.headers.cookie).state

    if(state !== stateCookie) {
        console.log(state)
        return res.status(403).send('request origin cannot be verified')
    }

    if(shop && hmac && code) {
        const map = Object.assign({}, req.query)
        delete map['hmac']
        const message = querystring.stringify(map)
        const generatedHash = crypto
            .createHmac('sha256', apiSecretKey)
            .update(message)
            .digest('hex')
        
        console.log('hash', generatedHash, hmac)
        if(generatedHash !== hmac) {
            return res.status(400).send('hmac validation failed')
        }

        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token'
        const accessTokenPayload = {
            client_id: apiKey,
            client_secret: apiSecretKey,
            code
        }

        request.post(accessTokenRequestUrl, { json: accessTokenPayload })
            .then((accessTokenResponse) => {
                const accessToken = accessTokenResponse.access_token
                
                const apiRequestUrl = 'https://' + shop + '/admin/products.json'
                const apiRequestHeader = {
                    'X-Shopify-Access-Token': accessToken
                }

                request.get(apiRequestUrl, { headers: apiRequestHeader })
                    .then((apiResponse) => {
                        res.end('<h1>Hello</h1>')
                    })
                    .catch((err) => {
                        res.status(err.statusCode).send(err)
                    })
            })
            .catch((err) => {
                res.status(err.statusCode).send(err)
            })

    } else {
        res.status(400).send('required parameters missing')
    }
})

app.post('/webhooks/orders/create', async (req, res) => {
    hmacHeader = req.headers['x-shopify-hmac-sha256']

    const data = JSON.stringify(req.body)

    const generatedHash = crypto
            .createHmac('sha256', apiSecretKey)
            .update(data)
            .digest('base64')
    
    console.log(generatedHash, hmacHeader)
    console.log('order created')

    res.status(200).send('ok')
    
})
// console.log(apiKey, apiSecretKey)

app.listen(3000, () => {
    console.log('Listening on port 3000')
})