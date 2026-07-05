//! actor.

// ---------------------------------------------------------------------------
// Actor & Resource
// ---------------------------------------------------------------------------

/// An actor who performed an auditable action.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Actor {
    pub id: String,
    pub name: String,
    pub role: String,
}

impl Actor {
    #[must_use]
    pub fn new(id: &str, name: &str, role: &str) -> Self {
        Self {
            id: id.to_owned(),
            name: name.to_owned(),
            role: role.to_owned(),
        }
    }
}

/// A resource that was affected by an auditable action.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Resource {
    pub kind: String,
    pub id: String,
    pub name: String,
}

impl Resource {
    #[must_use]
    pub fn new(kind: &str, id: &str, name: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            id: id.to_owned(),
            name: name.to_owned(),
        }
    }
}
