namespace eParty.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddPendingWhitelist : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.PendingWhitelist",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Payload = c.String(),
                        Token = c.String(),
                        CreatedAt = c.DateTime(nullable: false),
                        IsUsed = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
        }
        
        public override void Down()
        {
            DropTable("dbo.PendingWhitelist");
        }
    }
}
