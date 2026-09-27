[English](README.md) | **日本語**

# ALICE-Audit

[Project A.L.I.C.E.](https://github.com/anthropics/alice) の監査証跡システム

## 概要

`alice-audit` はハッシュチェーンによる改ざん検出、コンプライアンスレポート、保持ポリシー、構造化イベントクエリを備えた監査証跡システムです。

## 機能

- **ハッシュチェーン監査証跡** — 各イベントを前のイベントに暗号的に連鎖
- **改ざん検出** — チェーン全体または個別イベントの検証
- **重要度レベル** — Info、Warning、Error、Criticalの分類
- **アクター・リソース追跡** — 誰が何に対して何をしたかの構造化記録
- **メタデータ** — イベントごとの任意キー・バリューペア
- **保持ポリシー** — 時間ベースの自動イベント期限切れ
- **コンプライアンスレポート** — 期間・アクター・リソース別の監査レポート生成
- **イベントクエリ** — 監査ログの検索・フィルタリング

## クイックスタート

```rust
use alice_audit::{AuditTrail, Actor, Resource, Severity};

let mut trail = AuditTrail::new();
let actor = Actor::new("u-001", "Alice", "admin");
let resource = Resource::new("document", "d-42", "report.pdf");

trail.record(Severity::Info, actor, resource, "download", "ユーザーがレポートをダウンロード");
assert!(trail.verify_chain());
```

## アーキテクチャ

```
alice-audit
├── Severity         — イベント重要度分類
├── Actor            — アクションの実行者
├── Resource         — 影響を受けたリソース
├── AuditEvent       — ハッシュチェーンリンク付き単一イベント
├── AuditTrail       — チェーン検証付き追記専用ログ
├── RetentionPolicy  — 時間ベースのイベント有効期限
└── ComplianceReport — 構造化監査レポート
```

## ライセンス

`AGPL-3.0 OR LicenseRef-Commercial` — デュアルライセンス どちらかを選べる

| 選択肢 | 条文 | こういう時 |
|--------|------|-----------|
| **AGPL-3.0** | [LICENSE-AGPL](LICENSE-AGPL) — 無償、報告義務なし | 自分の project も AGPL 互換の OSS、または社内利用のみ |
| **商用ライセンス** | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) — 有償、コピーレフト義務を解除 | クローズドソース製品 / 商用 SaaS / エッジ・ファームウェア配布 / plugin 再配布 / ソース開示を禁じるプラットフォーム NDA |

AGPL は強いコピーレフト: `alice-audit` を link して配布 / 提供する製品・ファームウェア・
サービスは AGPL で公開する義務がある これはオープンなエコシステムのための意図的な
選択で、それが実行できない場合のために商用ライセンスを用意している

商用ライセンスの問い合わせ: <contact@extoria.co.jp>
