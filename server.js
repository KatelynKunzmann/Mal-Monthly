import fs from 'fs'
import cors from 'cors'
import express from 'express'
import fetch from 'node-fetch'

const app = express()

app.use(cors())
app.use(express.static("public"))
app.set('view engine', 'ejs')

app.get('/', (req, res) => {
    fetch('https://urlhaus.abuse.ch/downloads/csv_recent/')
        .then((response) => response.text())
        .then((body) => {
            var mal_array = formatData(body)
            var date = Date().toString()
            res.render('index', {
                data: mal_array,
                date: date
            })
        })
        .catch((error) => {
            console.log('error', error)
        })
})


/**
 * Captures csv, formats all data then writes it all to a JSON file
 * @param data = entire csv
 * @returns csv file, JSON file, and formatted data in an array for table
 */
function formatData(data) {
    var malwareObjectArr = []
    var mal_array = []

    var jsonData = JSON.stringify(data)

    // Splits title from column headings and body
    // body[0] = title
    var body = jsonData.split("\\r\\n#\\r\\n#")

    // Splits body into lines of data
    // lines[0] = column headings
    var lines = body[1].split("\\r\\n\\")

    for (let i = 1; i < lines.length; i++) {
        // Splits each line into fields; id, date_added, url, etc.
        var fields = lines[i].split(",\\")

        // Format data to get rid of quotes and slashes and to defang URLs
        let f_id = fields[0].replace(/[^0-9]/g, "")
        let f_date = fields[1].replace(/[^a-z0-9:-]/gi, " ")
        let f_url = fields[2].replace(/[^a-z0-9.:/]/gi, "")
        let defang_url = f_url.replace("http", "hxxp").replace(".", "[.]")
        let f_status = fields[3].replace(/[^a-z]/gi, "")
        let f_lastOnline = fields[4].replace(/[^a-z0-9:-]/gi, "")
        let f_threat = fields[5].replace(/[^a-z0-9_]/gi, "")
        let f_hash = "N/A"
        let f_tags = fields[6].replace(/[^a-z0-9,]/gi, "")
        let f_urlhaus_link = fields[7].replace(/[^a-z0-9.:/]/gi, "")
        let f_reporter = fields[8].replace(/[^a-z0-9-_]/gi, "")

        // Create json object for each
        let mal = {
            index: i,
            id: f_id,
            date_added: f_date,
            url: defang_url,
            status: f_status,
            last_online: f_lastOnline,
            threat: f_threat,
            hash: f_hash,
            tags: f_tags,
            urlhaus_link: f_urlhaus_link,
            reporter: f_reporter
        }
        // Add each malware object to an array for JSON file and table
        malwareObjectArr.push(mal)
        mal_array.push(mal)
    }

    // Create CSV file
    writeToCSVFile(data)

    // Create JSON file
    let malString = JSON.stringify(malwareObjectArr, null, 2)
    writeToJSONFile(malString)

    return mal_array;
}

/**
 * Create and write to a JSON file named mal-monthly_data.json
 * will be overwritten with latest data with each fetch
 * @param malwareObjects = all malware data to write to json file
 * @returns mal-monthly_data.json
 */
function writeToJSONFile(malwareObjects) {
    fs.writeFile("mal-monthly_data.json", malwareObjects, (err) => {
        if (err) throw err;
    })
    console.log("\nFind the JSON " +
        "file under .../mal-monthly/mal-monthly_data.json\n")
}

/**
 * Create and write to a CSV file named mal-monthly_data.csv
 * will be overwritten with latest data with each fetch
 * @param malware = all malware data to write to csv file
 * @returns mal-monthly_data.csv
 */
function writeToCSVFile(malware) {
    fs.writeFile("mal-monthly_data.csv", malware, (err) => {
        if (err) throw err;
    })
    console.log("\nFind the CSV " +
        "file under .../mal-monthly/mal-monthly_data.csv\n")
}

app.listen(3000, () => { console.log("Table is being rendered at: http://127.0.0.1:3000") })