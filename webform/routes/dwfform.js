var express = require('express');
var axios = require('axios');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {

	const the_username = req.session.github_login || undefined;

	if (the_username == undefined) {
		res.redirect("/");
	}

	res.render('dwfform', {
		title: 'Actual DWF Form',
		username: the_username
	});
});

router.post('/formsubmit', function(req, res, next) {

	if (process.env.DWF_VIEW_EDIT == "true") {
		// form fiew only dev mode
		res.redirect("/");
	} else {

		var redirect = "/";
		const the_username = req.session.github_login || undefined;

		if (the_username == undefined) {
			res.redirect("/");
		}

		const the_github_id = req.session.github_id;

		var refs = [];
		if (Array.isArray(req.body.references)) {
			refs = req.body.references;
		} else {
			refs = [req.body.references];
		}

		// We need to turn the form data into a structure, then into json
		dwf_data = {
			vendor_name: req.body.vendorName,
			product_name: req.body.productName,
			product_version: req.body.productVersion,
			vulnerability_type: req.body.vulnType,
			affected_component: req.body.affectedComponent,
			attack_vector: req.body.attackVector,
			impact: req.body.impact,
			credit: req.body.credit,
			references: refs,
			reporter: the_username,
			reporter_id: the_github_id,
			notes: req.body.notes
		};

		dwf_json = JSON.stringify(dwf_data, null, 2);

		//Create issue
		var body = {
			title: "DWF Request",
			body: `\`\`\`\n--- DWF JSON ---\n${dwf_json}\n--- DWF JSON ---\n\`\`\`\n/cc @${the_username}`,
			labels: ['new', 'check']
		};
		var opts = {
			headers: { accept: 'application/json' },
			auth: {
				username: process.env.GH_USERNAME,
				password: process.env.GH_TOKEN,
			}
		};
		var repo = process.env.GH_REPO
		axios.post(`https://api.github.com/repos/${repo}/issues`, body, opts)
		.then((resp) => {
			redirect = resp['data']['html_url'];
			res.redirect(redirect);
		})
		.catch((err) => {
					console.log(err)
					res.status(500).json({ message: "A bad thing happened" });
			})
	}

});

module.exports = router;
