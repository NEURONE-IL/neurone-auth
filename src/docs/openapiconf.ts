export default {
    "definition":{
        "openapi": "3.0.3",
        "info": {
            "version": "1.0.0",
            "title": "Neurone-Auth",
            "description": "Account auth manager for the NEURONE Framework.",
            "license": {
            "name": "AGPL-3.0",
            "url": "https://www.gnu.org/licenses/agpl-3.0.en.html"
            }
        },
        "servers": [
            {
                "url": "http://localhost:"  + process.env.PORT || 3005
            }
        ],
    },
    "apis": ["./src/routes/*.ts"]
    
}