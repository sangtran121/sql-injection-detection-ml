namespace eParty.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddReturnUrl : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.PendingWhitelist", "ReturnUrl", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.PendingWhitelist", "ReturnUrl");
        }
    }
}
