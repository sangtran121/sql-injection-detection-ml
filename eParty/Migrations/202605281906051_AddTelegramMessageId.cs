namespace eParty.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddTelegramMessageId : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.PendingWhitelist", "TelegramMessageId", c => c.Long(nullable: false));
        }
        
        public override void Down()
        {
            DropColumn("dbo.PendingWhitelist", "TelegramMessageId");
        }
    }
}
