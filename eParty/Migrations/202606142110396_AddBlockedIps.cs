namespace eParty.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddBlockedIps : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.BlockedIps",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        IpAddress = c.String(nullable: false, maxLength: 50),
                        Source = c.String(maxLength: 100),
                        Reason = c.String(maxLength: 500),
                        ChallengeCount = c.Int(nullable: false),
                        BlockedRequestCount = c.Int(nullable: false),
                        BlockedUntil = c.DateTime(nullable: false),
                        CreatedAt = c.DateTime(nullable: false),
                        LastUpdatedAt = c.DateTime(nullable: false),
                        UnblockedAt = c.DateTime(),
                        IsActive = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
        }
        
        public override void Down()
        {
            DropTable("dbo.BlockedIps");
        }
    }
}
