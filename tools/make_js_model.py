import json

with open("models/phishing_model.json", "r", encoding="utf-8") as f:
    model_data = json.load(f)

js_content = "/**\n * SafeSurf Pro - Embedded ML Model\n */\n"
js_content += "var PHISHING_MODEL = " + json.dumps(model_data) + ";\n"
js_content += "if (typeof globalThis !== 'undefined') globalThis.PHISHING_MODEL = PHISHING_MODEL;\n"
js_content += "if (typeof self !== 'undefined') self.PHISHING_MODEL = PHISHING_MODEL;\n"
js_content += "if (typeof module !== 'undefined' && module.exports) module.exports = PHISHING_MODEL;\n"

with open("models/phishing_model.js", "w", encoding="utf-8") as f:
    f.write(js_content)

print("Generated models/phishing_model.js successfully!")
