%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.


%Lower calculation
function Lower=LowerCalculation(Input, AttributeType)
    SampleNumber=size(Input,2);
    Lower=zeros(1,SampleNumber);
    for X=1:SampleNumber
        I=zeros(1,SampleNumber-1);
        RC=zeros(1,SampleNumber-1);
        RD=zeros(1,SampleNumber-1);
        Temp=repmat(Input(:,X),1,SampleNumber)-Input;%Subtract Xs' features from the other
        Temp(:,X)=[];%Remove it self
        Temp=1-(Temp.^2);%1-Distance(x,y):|x-y|^2
        Temp(find(Temp<0))=0;%max(0,1-sigma(x,y))
        Conditions=find(AttributeType==0);% 0 -> condition attribute
        Decisions=find(AttributeType==1);% 1 -> decision attribute
        
        switch numel(Conditions)
        case 1
            RC(1,:)=Temp(Conditions,:);
        case 2
            RC(1,:)=max(0,(Temp(Conditions(1),:)+Temp(Conditions(2),:)-1));
        otherwise
            RC(1,:)=max(0,(Temp(Conditions(1),:)+Temp(Conditions(2),:)-1));
            for i=3:numel(Conditions)
                RC(1,:)=max(0,(RC+Temp(Conditions(i),:)-1));
            end
        end
        
        RD(1,:)=Temp(Decisions,:);%We have just one decision attribute
        
        I(1,:)=min(1,1-RC+RD);%Implicators results
        
        %inf
        %Lower(X)=min(I);
        %OWA
        I=sort(I,'descend');
        Coefficent=1:SampleNumber-1;
        I=I.*Coefficent;
        I=I*(2/((SampleNumber-1)*SampleNumber));
        Lower(X)=sum(I);
    end
end