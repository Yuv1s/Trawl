//! Files a crawl never links to, found by asking for them by name.
//!
//! The passive crawl only reaches what a page points at, what a sitemap lists,
//! and the handful of sensitive paths [`crate::server`] tries outright. A flag
//! left at the web root that nothing links to, that robots does not name, sits
//! outside all of that. This is the sweep that reaches it: a list of the names
//! a file gets when someone leaves one lying around, each requested and kept
//! only when something real answers.
//!
//! The catch is the soft 404. Plenty of servers answer every path with 200 and
//! their front page, so a bare 200 proves nothing. Before the sweep runs it
//! asks for two paths that cannot exist and remembers what the answer looks
//! like. A probe is a hit only when it beats that: a real 200 on a server that
//! honestly 404s, or a body that does not match the catch-all on a server that
//! does not. It is the same read-the-negative-case-first discipline the archive
//! and PDF readers use, pointed at a web server.

/// How far a body length may drift from the soft-404 body and still count as the
/// same catch-all rather than a real file. Small, since a genuine file almost
/// never lands within a few bytes of the not-found page.
const SOFT_404_TOLERANCE: usize = 48;

/// What a not-found answer looks like on this server, learned by asking for
/// things that cannot be there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Baseline {
    /// True when a made-up path came back a success instead of a 404, so the
    /// status alone says nothing and the body has to be compared.
    soft: bool,
    /// The not-found status a straight server gives, kept so a path answering
    /// differently stands out.
    status: u16,
    /// The length of the not-found body, for telling a real page from the
    /// server's catch-all when it soft-404s.
    body_len: usize,
}

impl Baseline {
    /// Reads the calibration probes into a picture of "not found" here.
    ///
    /// The probes are paths that cannot exist, so whatever they share is the
    /// server's not-found answer. Two that both succeed mean it soft-404s and
    /// the body length is what a real file will have to differ from.
    pub fn from_samples(samples: &[(u16, usize)]) -> Baseline {
        let succeeded: Vec<&(u16, usize)> = samples
            .iter()
            .filter(|(status, _)| matches!(status, 200 | 206))
            .collect();

        // Every made-up path came back a success: the server soft-404s, and the
        // catch-all body length is the average of what it returned.
        if !succeeded.is_empty() && succeeded.len() == samples.len() {
            let total: usize = succeeded.iter().map(|(_, len)| *len).sum();
            return Baseline {
                soft: true,
                status: 200,
                body_len: total / succeeded.len(),
            };
        }

        Baseline {
            soft: false,
            status: samples.first().map(|(status, _)| *status).unwrap_or(404),
            body_len: 0,
        }
    }

    /// Whether a probed response is a real file rather than the server's
    /// not-found answer in disguise.
    pub fn is_hit(&self, status: u16, body_len: usize) -> bool {
        match status {
            200 | 206 => {
                if body_len == 0 {
                    return false;
                }
                if !self.soft {
                    return true;
                }
                // A soft-404 server returns its catch-all for everything, so a
                // real file is the one whose body does not match it.
                self.body_len.abs_diff(body_len) > SOFT_404_TOLERANCE
            }
            // A path that answers "forbidden" where nonsense answers "not
            // found" is a file that is there and guarded, which is worth
            // saying. Only trusted on a server that 404s honestly, since a
            // soft-404 one throws these around too.
            401 | 403 => !self.soft && self.status != status,
            _ => false,
        }
    }
}

/// Common names for files that carry a flag or the keys to one, and the
/// directories they get dropped in. Curated rather than exhaustive: this runs on
/// the person's own machine under a request budget, so it holds the names a
/// challenge actually uses, not a dictionary.
pub const DISCOVERY_PATHS: &[&str] = &[
    // The prize itself, however it was named and served.
    "/flag",
    "/flag.txt",
    "/flag.php",
    "/flag.html",
    "/flag.pdf",
    "/flag.zip",
    "/flag.png",
    "/flag.jpg",
    "/flag.json",
    "/flags.txt",
    "/flag1.txt",
    "/getflag",
    "/get_flag",
    "/flag.bak",
    // The keys to it.
    "/key",
    "/key.txt",
    "/secret",
    "/secret.txt",
    "/secrets.txt",
    "/password.txt",
    "/passwords.txt",
    "/creds.txt",
    "/id_rsa",
    "/.ssh/id_rsa",
    "/private.key",
    // Notes a person leaves themselves.
    "/note.txt",
    "/notes.txt",
    "/todo.txt",
    "/todo",
    "/readme.txt",
    "/humans.txt",
    "/.well-known/security.txt",
    // Source and configuration that should never have shipped.
    "/config.php",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/wp-config.php",
    "/settings.py",
    "/app.py",
    "/server.py",
    "/composer.json",
    "/package.json",
    "/.gitignore",
    "/Dockerfile",
    "/docker-compose.yml",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/upload.php",
    // Directories a listing or an index page falls out of.
    "/admin/",
    "/administrator/",
    "/uploads/",
    "/upload/",
    "/files/",
    "/backup/",
    "/backups/",
    "/secret/",
    "/hidden/",
    "/private/",
    "/dev/",
    "/test/",
    "/old/",
    "/data/",
];

/// Paths that cannot exist, for learning the server's not-found answer before
/// the real sweep. Two spellings, since a server can 404 a bare path and
/// soft-404 one that looks like a file, or the other way round.
pub fn calibration_paths(seed: u128) -> [String; 2] {
    [
        format!("/{seed:032x}"),
        format!("/{:032x}.html", seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)),
    ]
}

#[cfg(test)]
mod tests;
