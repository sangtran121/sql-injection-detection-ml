namespace eParty.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddSQLInjectionLog : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.SQLInjectionLog",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        Timestamp = c.DateTime(nullable: false),
                        IpAddress = c.String(),
                        Url = c.String(),
                        SuspiciousInput = c.String(),
                        Controller = c.String(),
                        Action = c.String(),
                        UserAgent = c.String(),
                        IsBlocked = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
        }
        
        public override void Down()
        {
            DropTable("dbo.SQLInjectionLog");
        }
    }
}
